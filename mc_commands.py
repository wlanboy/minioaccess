import ipaddress
import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

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

def _mc_host_url() -> str:
    parts = urlsplit(MINIO_ENDPOINT)
    if parts.scheme not in ("http", "https") or not parts.netloc:
        raise RuntimeError(f"MINIO_ENDPOINT muss mit http:// oder https:// beginnen: {MINIO_ENDPOINT!r}")
    user = quote(MINIO_ACCESS_KEY, safe="")
    password = quote(MINIO_SECRET_KEY, safe="")
    return f"{parts.scheme}://{user}:{password}@{parts.netloc}"


def _mc_env() -> dict[str, str]:
    return {**os.environ, f"MC_HOST_{MINIO_ALIAS}": _mc_host_url()}


def _describe(command: list[str]) -> str:
    """Name der mc-Aktion ohne Argumente (z. B. "admin user add") fürs Log."""
    words = []
    for word in command[1:]:
        if word.startswith("-"):
            continue
        if word == MINIO_ALIAS or word.startswith(f"{MINIO_ALIAS}/"):
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


def run_mc_command(command: list[str]) -> str:
    """Führt mc aus und gibt stdout zurück. Wirft McError bei Exit-Code ≠ 0, Timeout oder OSError."""
    action = _describe(command)
    try:
        result = subprocess.run(
            command, capture_output=True, text=True, check=False, env=_mc_env(), timeout=MC_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        logger.warning("mc %s: Timeout nach %.0f s", action, MC_TIMEOUT)
        raise McError(f"MinIO antwortet nicht (Timeout nach {MC_TIMEOUT:.0f} s).", 504) from None
    except OSError as e:
        logger.warning("mc %s fehlgeschlagen: %s", action, e)
        raise McError(f"mc konnte nicht gestartet werden: {e}", 500) from e

    logger.debug("mc %s: exit %d", action, result.returncode)
    if result.returncode != 0:
        logger.warning("mc %s fehlgeschlagen (exit %d)", action, result.returncode)
        raise McError(_error_message(result))
    return result.stdout.strip()


def _parse_ndjson(output: str) -> list[dict]:
    """Parst NDJSON (eine JSON-Objekt pro Zeile) und gibt erfolgreiche Einträge zurück."""
    results = []
    for line in output.split('\n'):
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
            if data.get("status") == "success":
                results.append(data)
        except json.JSONDecodeError:
            pass
    return results


def check_connection():
    """Prüft beim Start, ob mc ausführbar und MinIO mit den Admin-Credentials erreichbar ist."""
    if not (os.path.isfile(MC_BINARY) and os.access(MC_BINARY, os.X_OK)):
        raise RuntimeError(f"mc nicht gefunden oder nicht ausführbar: {MC_BINARY!r} (MC_BINARY setzen)")
    try:
        run_mc_command([MC_BINARY, "--json", "admin", "info", MINIO_ALIAS])
    except McError as e:
        raise RuntimeError(f"MinIO nicht erreichbar: {e}") from e
    logger.info("MinIO-Verbindung OK (%s → %s)", MINIO_ALIAS, MINIO_ENDPOINT)


def list_users():
    output = run_mc_command([MC_BINARY, "--json", "admin", "user", "list", MINIO_ALIAS])
    return [
        {"name": entry["accessKey"], "enabled": entry.get("userStatus") == "enabled"}
        for entry in _parse_ndjson(output)
        if "accessKey" in entry
    ]


def enable_user(access_key: str) -> str:
    _check(is_valid_access_key(access_key), "Benutzer", access_key)
    return run_mc_command([MC_BINARY, "--json", "admin", "user", "enable", MINIO_ALIAS, access_key])


def disable_user(access_key: str) -> str:
    _check(is_valid_access_key(access_key), "Benutzer", access_key)
    return run_mc_command([MC_BINARY, "--json", "admin", "user", "disable", MINIO_ALIAS, access_key])


def list_buckets():
    output = run_mc_command([MC_BINARY, "--json", "ls", MINIO_ALIAS])
    return [
        entry["key"].rstrip('/')
        for entry in _parse_ndjson(output)
        if entry.get("type") == "folder" and "key" in entry
    ]


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
    policy_name = f"{bucket}-{policy_type}"
    policy = {"Version": "2012-10-17", "Statement": policy_statements(bucket, policy_type)}

    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump(policy, f)
        temp_path = f.name

    try:
        run_mc_command([MC_BINARY, "--json", "admin", "policy", "create", MINIO_ALIAS, policy_name, temp_path])
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
    policy_name = f"{bucket}-{policy_type}"
    if policy_name in list_policies():
        return policy_name
    return create_bucket_policy(bucket, policy_type)


def get_bucket_policies(bucket: str):
    """Holt alle User-Policy-Zuordnungen für ein Bucket."""
    _check(is_valid_bucket(bucket), "Bucket", bucket)
    policies = []
    bucket_policy_prefix = f"{bucket}-"

    users = list_users()
    for user in users:
        username = user["name"]
        try:
            output = run_mc_command([MC_BINARY, "--json", "admin", "user", "info", MINIO_ALIAS, username])
        except McError as e:
            if e.status != 400:
                raise
            continue  # User zwischen list und info gelöscht
        try:
            data = json.loads(output)
            policy_string = data.get("policyName", "")
            if policy_string:
                for policy in [p.strip() for p in policy_string.split(",")]:
                    if policy and policy.startswith(bucket_policy_prefix):
                        policies.append({"user": username, "policy": policy})
        except json.JSONDecodeError:
            pass

    return policies


def list_policies() -> list[str]:
    """Listet alle vorhandenen Policies auf."""
    output = run_mc_command([MC_BINARY, "--json", "admin", "policy", "list", MINIO_ALIAS])
    return [
        entry["policy"]
        for entry in _parse_ndjson(output)
        if "policy" in entry
    ]


def _as_list(value) -> list:
    """Action/Resource dürfen in Policies ein String oder eine Liste sein."""
    if isinstance(value, str):
        return [value]
    return list(value or [])


def get_policy_details(policy_name: str) -> dict:
    """Gibt Actions und Resources einer Policy zurück."""
    output = run_mc_command([MC_BINARY, "--json", "admin", "policy", "info", MINIO_ALIAS, policy_name])
    try:
        data = json.loads(output)
    except json.JSONDecodeError:
        return {"name": policy_name, "actions": [], "resources": []}
    # mc admin policy info --json wraps the document: {"status":"success","policy":{...}}
    policy_doc = data.get("policy", data) if isinstance(data, dict) else {}
    actions: list[str] = []
    resources: list[str] = []
    for stmt in policy_doc.get("Statement", []) if isinstance(policy_doc, dict) else []:
        actions.extend(a for a in _as_list(stmt.get("Action")) if a not in actions)
        resources.extend(r for r in _as_list(stmt.get("Resource")) if r not in resources)
    return {"name": policy_name, "actions": actions, "resources": resources}


def delete_policy(policy_name: str) -> str:
    """Löscht eine Policy."""
    _check(is_valid_policy_name(policy_name), "Policy", policy_name)
    return run_mc_command([MC_BINARY, "--json", "admin", "policy", "remove", MINIO_ALIAS, policy_name])


def create_user(access_key: str, secret_key: str) -> str:
    """Erstellt einen neuen Benutzer."""
    _check(is_valid_access_key(access_key), "Benutzer", access_key)
    _check(is_valid_secret(secret_key), "Secret", secret_key)
    return run_mc_command([MC_BINARY, "--json", "admin", "user", "add", MINIO_ALIAS, access_key, secret_key])


def delete_user(access_key: str) -> str:
    """Löscht einen Benutzer."""
    _check(is_valid_access_key(access_key), "Benutzer", access_key)
    return run_mc_command([MC_BINARY, "--json", "admin", "user", "remove", MINIO_ALIAS, access_key])


def change_password(access_key: str, secret_key: str) -> str:
    """Ändert das Passwort eines Benutzers."""
    _check(is_valid_access_key(access_key), "Benutzer", access_key)
    _check(is_valid_secret(secret_key), "Secret", secret_key)
    return run_mc_command([MC_BINARY, "--json", "admin", "user", "add", MINIO_ALIAS, access_key, secret_key])


def create_bucket(bucket_name: str) -> str:
    """Erstellt einen neuen Bucket."""
    _check(is_valid_bucket(bucket_name), "Bucket", bucket_name)
    return run_mc_command([MC_BINARY, "--json", "mb", f"{MINIO_ALIAS}/{bucket_name}"])


def delete_bucket(bucket_name: str, force: bool = False) -> str:
    """Löscht einen Bucket. Ohne force schlägt das bei einem nicht leeren Bucket fehl."""
    _check(is_valid_bucket(bucket_name), "Bucket", bucket_name)
    flags = ["--force"] if force else []
    return run_mc_command([MC_BINARY, "--json", "rb", *flags, f"{MINIO_ALIAS}/{bucket_name}"])


def attach_policy(policy_name: str, user: str) -> str:
    """Weist einem Benutzer eine Policy zu."""
    _check(is_valid_policy_name(policy_name), "Policy", policy_name)
    _check(is_valid_access_key(user), "Benutzer", user)
    return run_mc_command([MC_BINARY, "--json", "admin", "policy", "attach", MINIO_ALIAS, policy_name, "--user", user])


def detach_policy(policy_name: str, user: str) -> str:
    """Entfernt eine Policy von einem Benutzer."""
    _check(is_valid_policy_name(policy_name), "Policy", policy_name)
    _check(is_valid_access_key(user), "Benutzer", user)
    return run_mc_command([MC_BINARY, "--json", "admin", "policy", "detach", MINIO_ALIAS, policy_name, "--user", user])
