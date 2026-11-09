import ipaddress
import json
import logging
import os
import re
import subprocess
import tempfile
from urllib.parse import quote, urlsplit

from dotenv import load_dotenv

load_dotenv()

MC_BINARY = "./mc"

logger = logging.getLogger(__name__)


def _require_env(name: str) -> str:
    value = os.getenv(name)
    if value is None:
        raise RuntimeError(f"Required environment variable '{name}' is not set")
    return value


MINIO_ALIAS = _require_env("MINIO_ALIAS")
MINIO_ENDPOINT = _require_env("MINIO_ENDPOINT")
MINIO_ACCESS_KEY = _require_env("MINIO_ACCESS_KEY")
MINIO_SECRET_KEY = _require_env("MINIO_SECRET_KEY")


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


def run_mc_command(command: list[str]) -> str:
    action = _describe(command)
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=False, env=_mc_env())
        logger.debug("mc %s: exit %d", action, result.returncode)
        if result.returncode != 0:
            logger.warning("mc %s fehlgeschlagen (exit %d)", action, result.returncode)
            error_output = result.stdout.strip() or result.stderr.strip()
            try:
                data = json.loads(error_output.split('\n')[0])
                msg = (data.get("error") or {}).get("message", error_output)
                return f"Error: {msg}"
            except (json.JSONDecodeError, AttributeError):
                return f"Error: {error_output}"
        return result.stdout.strip()
    except (OSError, subprocess.SubprocessError) as e:
        logger.warning("mc %s fehlgeschlagen: %s", action, e)
        return f"Error: {e}"


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
    """Prüft beim Start, ob MinIO mit den Admin-Credentials erreichbar ist."""
    output = run_mc_command([MC_BINARY, "--json", "admin", "info", MINIO_ALIAS])
    if output.startswith("Error"):
        raise RuntimeError(f"MinIO nicht erreichbar: {output}")
    logger.info("MinIO-Verbindung OK (%s → %s)", MINIO_ALIAS, MINIO_ENDPOINT)


def list_users():
    output = run_mc_command([MC_BINARY, "--json", "admin", "user", "list", MINIO_ALIAS])
    if output.startswith("Error"):
        return []
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
    if output.startswith("Error"):
        return []
    return [
        entry["key"].rstrip('/')
        for entry in _parse_ndjson(output)
        if entry.get("type") == "folder" and "key" in entry
    ]


def get_policy_actions(policy_type: str) -> list:
    """Gibt die Actions für einen Policy-Typ zurück."""
    if policy_type == "readonly":
        return ["s3:GetBucketLocation", "s3:GetObject", "s3:ListBucket"]
    elif policy_type == "readwrite":
        return ["s3:*"]
    elif policy_type == "writeonly":
        return ["s3:PutObject"]
    return []


def create_bucket_policy(bucket: str, policy_type: str) -> str:
    """Erstellt eine bucket-spezifische Policy und gibt den Policy-Namen zurück."""
    _check(is_valid_bucket(bucket), "Bucket", bucket)
    policy_name = f"{bucket}-{policy_type}"
    actions = get_policy_actions(policy_type)

    if not actions:
        return f"Error: Unbekannter Policy-Typ '{policy_type}'"

    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": actions,
                "Resource": [
                    f"arn:aws:s3:::{bucket}",
                    f"arn:aws:s3:::{bucket}/*"
                ]
            }
        ]
    }

    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump(policy, f)
        temp_path = f.name

    try:
        result = run_mc_command([MC_BINARY, "--json", "admin", "policy", "create", MINIO_ALIAS, policy_name, temp_path])
        if "Error" in result and "already exists" in result:
            return policy_name
        elif "Error" in result:
            return result
        return policy_name
    finally:
        os.unlink(temp_path)


def ensure_bucket_policy(bucket: str, policy_type: str) -> str:
    """Stellt sicher, dass eine bucket-spezifische Policy existiert."""
    _check(is_valid_bucket(bucket), "Bucket", bucket)
    _check(policy_type in POLICY_TYPES, "Policy-Typ", policy_type)
    policy_name = f"{bucket}-{policy_type}"
    output = run_mc_command([MC_BINARY, "--json", "admin", "policy", "info", MINIO_ALIAS, policy_name])
    if "Error" in output:
        return create_bucket_policy(bucket, policy_type)
    return policy_name


def get_bucket_policies(bucket: str):
    """Holt alle User-Policy-Zuordnungen für ein Bucket."""
    _check(is_valid_bucket(bucket), "Bucket", bucket)
    policies = []
    bucket_policy_prefix = f"{bucket}-"

    users = list_users()
    for user in users:
        username = user["name"]
        output = run_mc_command([MC_BINARY, "--json", "admin", "user", "info", MINIO_ALIAS, username])
        if output.startswith("Error"):
            continue
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
    if output.startswith("Error") or not output:
        return []
    return [
        entry["policy"]
        for entry in _parse_ndjson(output)
        if "policy" in entry
    ]


def get_policy_details(policy_name: str) -> dict:
    """Gibt Actions und Resources einer Policy zurück."""
    output = run_mc_command([MC_BINARY, "--json", "admin", "policy", "info", MINIO_ALIAS, policy_name])
    if output.startswith("Error"):
        return {"name": policy_name, "actions": [], "resources": []}
    try:
        data = json.loads(output)
        # mc admin policy info --json wraps the document: {"status":"success","policy":{...}}
        policy_doc = data.get("policy", data)
        statements = policy_doc.get("Statement", [])
        actions: list[str] = []
        resources: list[str] = []
        for stmt in statements:
            actions.extend(stmt.get("Action", []))
            resources.extend(stmt.get("Resource", []))
        return {"name": policy_name, "actions": actions, "resources": resources}
    except (json.JSONDecodeError, AttributeError):
        return {"name": policy_name, "actions": [], "resources": []}


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


def delete_bucket(bucket_name: str) -> str:
    """Löscht einen Bucket."""
    _check(is_valid_bucket(bucket_name), "Bucket", bucket_name)
    return run_mc_command([MC_BINARY, "--json", "rb", "--force", f"{MINIO_ALIAS}/{bucket_name}"])


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
