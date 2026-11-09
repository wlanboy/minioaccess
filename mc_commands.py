import ipaddress
import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from urllib.parse import quote, urlsplit

from dotenv import load_dotenv

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class Settings:
    """Konfiguration aus der Umgebung. Wird im lifespan geladen, nicht beim Import."""

    alias: str
    endpoint: str
    access_key: str
    secret_key: str
    mc_binary: str = "./mc"
    mc_timeout: float = 15.0

    def __post_init__(self):
        parts = urlsplit(self.endpoint)
        if parts.scheme not in ("http", "https") or not parts.netloc:
            raise RuntimeError(f"MINIO_ENDPOINT muss mit http:// oder https:// beginnen: {self.endpoint!r}")


def _require_env(name: str) -> str:
    value = os.getenv(name)
    if value is None:
        raise RuntimeError(f"Required environment variable '{name}' is not set")
    return value


def load_settings() -> Settings:
    """Liest .env und Umgebung. MC_BINARY fehlt → mc aus dem PATH, sonst ./mc (lokale Entwicklung)."""
    load_dotenv()
    return Settings(
        alias=_require_env("MINIO_ALIAS"),
        endpoint=_require_env("MINIO_ENDPOINT"),
        access_key=_require_env("MINIO_ACCESS_KEY"),
        secret_key=_require_env("MINIO_SECRET_KEY"),
        mc_binary=os.getenv("MC_BINARY") or shutil.which("mc") or "./mc",
        mc_timeout=float(os.getenv("MC_TIMEOUT", "15")),
    )


_settings: Settings | None = None


def configure(settings: Settings | None) -> None:
    global _settings
    _settings = settings


def settings() -> Settings:
    if _settings is None:
        raise RuntimeError("mc_commands ist nicht konfiguriert (configure(load_settings()) fehlt)")
    return _settings


# ---------------------------------------------------------------------------
# Eingabeprüfung
# ---------------------------------------------------------------------------
# Alle Werte landen als Argumente im mc-Aufruf. Was mit "-" beginnt, liest mc
# als Flag (z. B. "--insecure"), deshalb ist "-" am Anfang nirgends erlaubt.

POLICY_TYPES = ("readonly", "readwrite", "writeonly")
# S3-Regeln: 3–63 Zeichen, Kleinbuchstaben/Ziffern/Punkt/Bindestrich.
_BUCKET_RE = re.compile(r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")
_ACCESS_KEY_RE = re.compile(r"^(?!-)[A-Za-z0-9._@=+,-]{3,128}$")
_POLICY_NAME_RE = re.compile(r"^(?!-)[A-Za-z0-9._@=+,-]{1,128}$")


def is_valid_bucket(name: str) -> bool:
    if not _BUCKET_RE.fullmatch(name) or ".." in name:
        return False
    try:
        ipaddress.IPv4Address(name)
        return False
    except ValueError:
        return True


def is_valid_access_key(name: str) -> bool:
    return bool(_ACCESS_KEY_RE.fullmatch(name))


def is_valid_policy_name(name: str) -> bool:
    return bool(_POLICY_NAME_RE.fullmatch(name))


def is_valid_secret(secret: str) -> bool:
    return not secret.startswith("-")


def _check(valid: bool, label: str, value: str):
    """Letzte Sicherung vor dem mc-Aufruf; die API prüft vorher selbst und meldet 400."""
    if not valid:
        raise ValueError(f"Ungültiger Wert für {label}: {value!r}")


# ---------------------------------------------------------------------------
# mc-Aufruf
# ---------------------------------------------------------------------------
# Kein "mc alias set": Das Secret stünde sonst in /proc/<pid>/cmdline und in
# ~/.mc/config.json. mc liest den Alias stattdessen aus MC_HOST_<alias>, das
# nur in der Umgebung des Subprozesses steht.

def _mc_host_url(cfg: Settings) -> str:
    parts = urlsplit(cfg.endpoint)
    user = quote(cfg.access_key, safe="")
    password = quote(cfg.secret_key, safe="")
    return f"{parts.scheme}://{user}:{password}@{parts.netloc}"


def _mc_env(cfg: Settings) -> dict[str, str]:
    return {**os.environ, f"MC_HOST_{cfg.alias}": _mc_host_url(cfg)}


def _alias() -> str:
    return settings().alias


def _target(name: str) -> str:
    return f"{_alias()}/{name}"


def _describe(args: list[str], alias: str) -> str:
    """Name der mc-Aktion ohne Argumente (z. B. "admin user add") fürs Log."""
    words = []
    for word in args:
        if word.startswith("-"):
            continue
        if word == alias or word.startswith(f"{alias}/"):
            break
        words.append(word)
    return " ".join(words)


class McError(Exception):
    """mc ist fehlgeschlagen. `status` ist der HTTP-Status, den die API daraus macht."""

    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.message = message
        self.status = status


def _error_message(result: subprocess.CompletedProcess) -> str:
    output = result.stdout.strip() or result.stderr.strip()
    try:
        data = json.loads(output.split("\n")[0])
        return (data.get("error") or {}).get("message") or output
    except (json.JSONDecodeError, AttributeError):
        return output or f"exit {result.returncode}"


def run_mc_command(args: list[str]) -> str:
    """Führt `mc --json <args>` aus und gibt stdout zurück.

    Wirft McError bei Exit-Code ≠ 0, Timeout oder OSError. Geloggt werden nur
    Aktion, Exit-Code und Dauer, nie Argumente oder Ausgabe (Secrets).
    """
    cfg = settings()
    action = _describe(args, cfg.alias)
    start = time.monotonic()
    try:
        result = subprocess.run(
            [cfg.mc_binary, "--json", *args],
            capture_output=True, text=True, check=False, env=_mc_env(cfg), timeout=cfg.mc_timeout,
        )
    except subprocess.TimeoutExpired:
        logger.warning("mc %s: Timeout nach %.0f s", action, cfg.mc_timeout)
        raise McError(f"MinIO antwortet nicht (Timeout nach {cfg.mc_timeout:.0f} s).", 504) from None
    except OSError as e:
        logger.warning("mc %s fehlgeschlagen: %s", action, e)
        raise McError(f"mc konnte nicht gestartet werden: {e}", 500) from e

    elapsed_ms = (time.monotonic() - start) * 1000
    if result.returncode != 0:
        logger.warning("mc %s fehlgeschlagen (exit %d, %.0f ms)", action, result.returncode, elapsed_ms)
        raise McError(_error_message(result))
    logger.debug("mc %s: exit 0, %.0f ms", action, elapsed_ms)
    return result.stdout.strip()


def _parse_ndjson(output: str) -> list[dict]:
    """Parst NDJSON (ein JSON-Objekt pro Zeile) und gibt erfolgreiche Einträge zurück."""
    results = []
    for line in output.split("\n"):
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(data, dict) and data.get("status") == "success":
            results.append(data)
    return results


def _split_policies(policy_name: str | None) -> list[str]:
    """mc liefert mehrere Policies eines Users kommasepariert in `policyName`."""
    return [p.strip() for p in (policy_name or "").split(",") if p.strip()]


def check_connection():
    """Prüft beim Start, ob mc ausführbar und MinIO mit den Admin-Credentials erreichbar ist."""
    cfg = settings()
    if not (os.path.isfile(cfg.mc_binary) and os.access(cfg.mc_binary, os.X_OK)):
        raise RuntimeError(f"mc nicht gefunden oder nicht ausführbar: {cfg.mc_binary!r} (MC_BINARY setzen)")
    try:
        run_mc_command(["admin", "info", cfg.alias])
    except McError as e:
        raise RuntimeError(f"MinIO nicht erreichbar: {e}") from e
    logger.info("MinIO-Verbindung OK (%s → %s)", cfg.alias, cfg.endpoint)


# ---------------------------------------------------------------------------
# Users
# ---------------------------------------------------------------------------

def _user_entries() -> list[dict]:
    """`admin user list` liefert pro User accessKey, userStatus und policyName."""
    output = run_mc_command(["admin", "user", "list", _alias()])
    return [entry for entry in _parse_ndjson(output) if "accessKey" in entry]


def list_users():
    return [
        {"name": entry["accessKey"], "enabled": entry.get("userStatus") == "enabled"}
        for entry in _user_entries()
    ]


def enable_user(access_key: str) -> str:
    _check(is_valid_access_key(access_key), "Benutzer", access_key)
    return run_mc_command(["admin", "user", "enable", _alias(), access_key])


def disable_user(access_key: str) -> str:
    _check(is_valid_access_key(access_key), "Benutzer", access_key)
    return run_mc_command(["admin", "user", "disable", _alias(), access_key])


def create_user(access_key: str, secret_key: str) -> str:
    """Erstellt einen neuen Benutzer."""
    _check(is_valid_access_key(access_key), "Benutzer", access_key)
    _check(is_valid_secret(secret_key), "Secret", secret_key)
    return run_mc_command(["admin", "user", "add", _alias(), access_key, secret_key])


def delete_user(access_key: str) -> str:
    """Löscht einen Benutzer."""
    _check(is_valid_access_key(access_key), "Benutzer", access_key)
    return run_mc_command(["admin", "user", "remove", _alias(), access_key])


def change_password(access_key: str, secret_key: str) -> str:
    """Ändert das Passwort eines Benutzers."""
    _check(is_valid_access_key(access_key), "Benutzer", access_key)
    _check(is_valid_secret(secret_key), "Secret", secret_key)
    return run_mc_command(["admin", "user", "add", _alias(), access_key, secret_key])


# ---------------------------------------------------------------------------
# Buckets
# ---------------------------------------------------------------------------

def list_buckets():
    output = run_mc_command(["ls", _alias()])
    return [
        entry["key"].rstrip("/")
        for entry in _parse_ndjson(output)
        if entry.get("type") == "folder" and "key" in entry
    ]


def create_bucket(bucket_name: str) -> str:
    """Erstellt einen neuen Bucket."""
    _check(is_valid_bucket(bucket_name), "Bucket", bucket_name)
    return run_mc_command(["mb", _target(bucket_name)])


def delete_bucket(bucket_name: str, force: bool = False) -> str:
    """Löscht einen Bucket. Ohne force schlägt das bei einem nicht leeren Bucket fehl."""
    _check(is_valid_bucket(bucket_name), "Bucket", bucket_name)
    flags = ["--force"] if force else []
    return run_mc_command(["rb", *flags, _target(bucket_name)])


# ---------------------------------------------------------------------------
# Policies
# ---------------------------------------------------------------------------

def bucket_policy_name(bucket: str, policy_type: str) -> str:
    return f"{bucket}-{policy_type}"


def policy_statements(bucket: str, policy_type: str) -> list[dict]:
    """Statements einer bucket-spezifischen Policy.

    Bucket-Actions gelten für arn:aws:s3:::bucket, Objekt-Actions für arn:aws:s3:::bucket/*.
    """
    bucket_arn = f"arn:aws:s3:::{bucket}"
    objects_arn = f"arn:aws:s3:::{bucket}/*"
    if policy_type == "readonly":
        bucket_actions = ["s3:GetBucketLocation", "s3:ListBucket"]
        object_actions = ["s3:GetObject"]
    elif policy_type == "writeonly":
        # Multipart-Uploads (große Dateien) brauchen mehr als PutObject.
        bucket_actions = ["s3:GetBucketLocation", "s3:ListBucketMultipartUploads"]
        object_actions = ["s3:PutObject", "s3:AbortMultipartUpload", "s3:ListMultipartUploadParts"]
    elif policy_type == "readwrite":
        return [{"Effect": "Allow", "Action": ["s3:*"], "Resource": [bucket_arn, objects_arn]}]
    else:
        raise ValueError(f"Unbekannter Policy-Typ: {policy_type!r}")
    return [
        {"Effect": "Allow", "Action": bucket_actions, "Resource": [bucket_arn]},
        {"Effect": "Allow", "Action": object_actions, "Resource": [objects_arn]},
    ]


def create_bucket_policy(bucket: str, policy_type: str) -> str:
    """Erstellt eine bucket-spezifische Policy und gibt den Policy-Namen zurück."""
    _check(is_valid_bucket(bucket), "Bucket", bucket)
    _check(policy_type in POLICY_TYPES, "Policy-Typ", policy_type)
    policy_name = bucket_policy_name(bucket, policy_type)
    policy = {"Version": "2012-10-17", "Statement": policy_statements(bucket, policy_type)}

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(policy, f)
        temp_path = f.name

    try:
        run_mc_command(["admin", "policy", "create", _alias(), policy_name, temp_path])
    except McError as e:
        if "already exists" not in e.message:
            raise
    finally:
        os.unlink(temp_path)
    return policy_name


def ensure_bucket_policy(bucket: str, policy_type: str) -> str:
    """Stellt sicher, dass eine bucket-spezifische Policy existiert, und gibt ihren Namen zurück."""
    _check(is_valid_bucket(bucket), "Bucket", bucket)
    _check(policy_type in POLICY_TYPES, "Policy-Typ", policy_type)
    policy_name = bucket_policy_name(bucket, policy_type)
    if policy_name in list_policies():
        return policy_name
    return create_bucket_policy(bucket, policy_type)


def get_bucket_policies(bucket: str) -> list[dict]:
    """User-Policy-Zuordnungen eines Buckets aus einem einzigen `admin user list`.

    Berücksichtigt nur die von dieser App angelegten Policies <bucket>-<typ>.
    Ein Präfixvergleich auf "<bucket>-" würde bei Bucket "data" auch die
    Policies von "data-backup" zeigen.
    """
    _check(is_valid_bucket(bucket), "Bucket", bucket)
    own = {bucket_policy_name(bucket, t) for t in POLICY_TYPES}
    return [
        {"user": entry["accessKey"], "policy": policy}
        for entry in _user_entries()
        for policy in _split_policies(entry.get("policyName"))
        if policy in own
    ]


def list_policies() -> list[str]:
    """Listet alle vorhandenen Policies auf."""
    output = run_mc_command(["admin", "policy", "list", _alias()])
    return [entry["policy"] for entry in _parse_ndjson(output) if "policy" in entry]


def _as_list(value) -> list:
    """Action/Resource dürfen in Policies ein String oder eine Liste sein."""
    if isinstance(value, str):
        return [value]
    return list(value or [])


def get_policy_details(policy_name: str) -> dict:
    """Gibt Actions und Resources einer Policy zurück."""
    output = run_mc_command(["admin", "policy", "info", _alias(), policy_name])
    try:
        data = json.loads(output)
    except json.JSONDecodeError:
        return {"name": policy_name, "actions": [], "resources": []}
    # mc admin policy info --json verpackt das Dokument: {"status":"success","policy":{...}}
    policy_doc = data.get("policy", data) if isinstance(data, dict) else {}
    actions: list[str] = []
    resources: list[str] = []
    for stmt in policy_doc.get("Statement", []) if isinstance(policy_doc, dict) else []:
        actions.extend(a for a in _as_list(stmt.get("Action")) if a not in actions)
        resources.extend(r for r in _as_list(stmt.get("Resource")) if r not in resources)
    return {"name": policy_name, "actions": actions, "resources": resources}


POLICY_DETAIL_WORKERS = 8


def list_policy_details() -> list[dict]:
    """Details aller Policies. mc liefert das Dokument nur per `policy info`, einzeln
    pro Policy; die Aufrufe laufen deshalb parallel (Reihenfolge bleibt erhalten)."""
    names = list_policies()
    if not names:
        return []
    with ThreadPoolExecutor(max_workers=min(POLICY_DETAIL_WORKERS, len(names))) as pool:
        return list(pool.map(get_policy_details, names))


def delete_policy(policy_name: str) -> str:
    """Löscht eine Policy."""
    _check(is_valid_policy_name(policy_name), "Policy", policy_name)
    return run_mc_command(["admin", "policy", "remove", _alias(), policy_name])


def attach_policy(policy_name: str, user: str) -> str:
    """Weist einem Benutzer eine Policy zu."""
    _check(is_valid_policy_name(policy_name), "Policy", policy_name)
    _check(is_valid_access_key(user), "Benutzer", user)
    return run_mc_command(["admin", "policy", "attach", _alias(), policy_name, "--user", user])


def detach_policy(policy_name: str, user: str) -> str:
    """Entfernt eine Policy von einem Benutzer."""
    _check(is_valid_policy_name(policy_name), "Policy", policy_name)
    _check(is_valid_access_key(user), "Benutzer", user)
    return run_mc_command(["admin", "policy", "detach", _alias(), policy_name, "--user", user])
