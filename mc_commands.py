import os
import json
import subprocess
import tempfile
from dotenv import load_dotenv

load_dotenv()

MC_BINARY = "./mc"
MINIO_ALIAS = os.getenv("MINIO_ALIAS")
MINIO_ENDPOINT = os.getenv("MINIO_ENDPOINT")
MINIO_ACCESS_KEY = os.getenv("MINIO_ACCESS_KEY")
MINIO_SECRET_KEY = os.getenv("MINIO_SECRET_KEY")


def run_mc_command(command):
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        print(f"MC Command: {result.stdout}")
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        return f"Error: {e.stderr.strip()}"


def setup_mc_alias():
    command = [MC_BINARY, "alias", "set", MINIO_ALIAS, MINIO_ENDPOINT, MINIO_ACCESS_KEY, MINIO_SECRET_KEY]
    output = run_mc_command(command)
    print(f"MC Alias Setup: {output}")


def list_users():
    output = run_mc_command([MC_BINARY, "admin", "user", "list", MINIO_ALIAS])
    if output.startswith("Error"):
        return []

    users = []
    for line in output.split('\n'):
        parts = line.split()
        if len(parts) >= 2:
            users.append(parts[1])
    return users


def list_buckets():
    output = run_mc_command([MC_BINARY, "ls", MINIO_ALIAS])
    return [line.strip().split()[-1] for line in output.split('\n') if line.strip() and not line.startswith("mc: <") and not line.startswith("mc: ERROR")]


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

    # Policy als temporäre Datei speichern und erstellen
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump(policy, f)
        temp_path = f.name

    try:
        result = run_mc_command([MC_BINARY, "admin", "policy", "create", MINIO_ALIAS, policy_name, temp_path])
        if "Error" in result and "already exists" in result:
            # Policy existiert bereits, das ist OK
            return policy_name
        elif "Error" in result:
            return result
        return policy_name
    finally:
        os.unlink(temp_path)


def ensure_bucket_policy(bucket: str, policy_type: str) -> str:
    """Stellt sicher, dass eine bucket-spezifische Policy existiert."""
    policy_name = f"{bucket}-{policy_type}"

    # Prüfen ob Policy bereits existiert
    output = run_mc_command([MC_BINARY, "admin", "policy", "info", MINIO_ALIAS, policy_name])

    if "Error" in output:
        # Policy existiert nicht, erstellen
        return create_bucket_policy(bucket, policy_type)

    return policy_name


def get_bucket_policies(bucket: str):
    """Holt alle User-Policy-Zuordnungen für ein Bucket."""
    policies = []
    # Bucket-spezifische Policy-Namen (z.B. "spring-readonly", "spring-readwrite")
    bucket_policy_prefix = f"{bucket}-"

    users = list_users()
    for user in users:
        user_info = run_mc_command([MC_BINARY, "admin", "user", "info", MINIO_ALIAS, user])
        if "Error" not in user_info:
            for line in user_info.split('\n'):
                if "PolicyName:" in line:
                    policy_string = line.split(":", 1)[-1].strip()
                    if policy_string:
                        # Policies sind durch Komma getrennt (z.B. "spring-readonly,spring-readwrite")
                        individual_policies = [p.strip() for p in policy_string.split(",")]
                        for policy in individual_policies:
                            # Nur bucket-spezifische Policies anzeigen
                            if policy and policy.startswith(bucket_policy_prefix):
                                policies.append({
                                    "user": user,
                                    "policy": policy
                                })

    return policies


def create_user(access_key: str, secret_key: str) -> str:
    """Erstellt einen neuen Benutzer."""
    result = run_mc_command([MC_BINARY, "admin", "user", "add", MINIO_ALIAS, access_key, secret_key])
    return result


def delete_user(access_key: str) -> str:
    """Löscht einen Benutzer."""
    result = run_mc_command([MC_BINARY, "admin", "user", "remove", MINIO_ALIAS, access_key])
    return result


def change_password(access_key: str, secret_key: str) -> str:
    """Ändert das Passwort eines Benutzers."""
    # mc admin user add mit existierendem User ändert das Passwort
    result = run_mc_command([MC_BINARY, "admin", "user", "add", MINIO_ALIAS, access_key, secret_key])
    return result


def create_bucket(bucket_name: str) -> str:
    """Erstellt einen neuen Bucket."""
    result = run_mc_command([MC_BINARY, "mb", f"{MINIO_ALIAS}/{bucket_name}"])
    return result


def delete_bucket(bucket_name: str) -> str:
    """Löscht einen Bucket."""
    result = run_mc_command([MC_BINARY, "rb", "--force", f"{MINIO_ALIAS}/{bucket_name}"])
    return result


def attach_policy(policy_name: str, user: str) -> str:
    """Weist einem Benutzer eine Policy zu."""
    result = run_mc_command([MC_BINARY, "admin", "policy", "attach", MINIO_ALIAS, policy_name, "--user", user])
    return result


def detach_policy(policy_name: str, user: str) -> str:
    """Entfernt eine Policy von einem Benutzer."""
    result = run_mc_command([MC_BINARY, "admin", "policy", "detach", MINIO_ALIAS, policy_name, "--user", user])
    return result
