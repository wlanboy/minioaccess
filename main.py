import os
import json
import subprocess
import tempfile
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
from dotenv import load_dotenv

load_dotenv()


@asynccontextmanager
async def lifespan(_app: FastAPI):
    setup_mc_alias()
    yield


app = FastAPI(lifespan=lifespan)
app.add_middleware(SessionMiddleware, secret_key=os.urandom(24).hex())
app.mount("/static", StaticFiles(directory="static"), name="static")

templates = Jinja2Templates(directory="templates")

MC_BINARY = "./mc"
MINIO_ALIAS = os.getenv("MINIO_ALIAS")
MINIO_ENDPOINT = os.getenv("MINIO_ENDPOINT")
MINIO_ACCESS_KEY = os.getenv("MINIO_ACCESS_KEY")
MINIO_SECRET_KEY = os.getenv("MINIO_SECRET_KEY")


def run_mc_command(command):
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        print(f"MC Alias Command: {result.stdout}")
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


@app.get("/", response_class=HTMLResponse)
async def index_get(request: Request):
    message = request.session.pop("message", None)
    users = list_users()
    buckets = list_buckets()
    return templates.TemplateResponse("index.html", {
        "request": request,
        "users": users,
        "buckets": buckets,
        "message": message
    })


@app.post("/", response_class=HTMLResponse)
async def index_post(
    request: Request,
    action: str = Form(...),
    access_key: str = Form(None),
    secret_key: str = Form(None),
    bucket_name: str = Form(None),
    policy_user: str = Form(None),
    policy_name: str = Form(None)
):
    message = ""

    # Benutzerverwaltung
    if action == "create_user":
        if not access_key or not access_key.strip():
            message = "Fehler: Benutzername darf nicht leer sein."
        elif not secret_key or len(secret_key) < 12:
            message = "Fehler: Das Secret muss mindestens 12 Zeichen lang sein."
        else:
            result = run_mc_command([MC_BINARY, "admin", "user", "add", MINIO_ALIAS, access_key.strip(), secret_key])
            message = result if "Error" in result else f"Benutzer '{access_key.strip()}' erstellt."
    elif action == "delete_user":
        if not access_key or not access_key.strip():
            message = "Fehler: Benutzername darf nicht leer sein."
        else:
            result = run_mc_command([MC_BINARY, "admin", "user", "remove", MINIO_ALIAS, access_key.strip()])
            message = result if "Error" in result else f"Benutzer '{access_key.strip()}' gelöscht."

    # Bucket-Verwaltung
    elif action == "create_bucket":
        if not bucket_name or not bucket_name.strip():
            message = "Fehler: Bucket-Name darf nicht leer sein."
        else:
            result = run_mc_command([MC_BINARY, "mb", f"{MINIO_ALIAS}/{bucket_name.strip()}"])
            message = result if "Error" in result else f"Bucket '{bucket_name.strip()}' erstellt."
    elif action == "delete_bucket":
        if not bucket_name or not bucket_name.strip():
            message = "Fehler: Bucket-Name darf nicht leer sein."
        else:
            result = run_mc_command([MC_BINARY, "rb", "--force", f"{MINIO_ALIAS}/{bucket_name.strip()}"])
            message = result if "Error" in result else f"Bucket '{bucket_name.strip()}' gelöscht."

    # Policy-Verwaltung
    elif action == "set_policy":
        user = policy_user
        result = run_mc_command([MC_BINARY, "admin", "policy", "attach", MINIO_ALIAS, policy_name, "--user", user])
        message = result if "Error" in result else f"Policy '{policy_name}' für Benutzer '{user}' gesetzt."

    request.session["message"] = message
    return RedirectResponse(url="/", status_code=303)


@app.get("/bucket/{bucket_name}", response_class=HTMLResponse)
async def bucket_details(request: Request, bucket_name: str):
    message = request.session.pop("message", None)
    policies = get_bucket_policies(bucket_name)
    users = list_users()
    return templates.TemplateResponse("bucket.html", {
        "request": request,
        "bucket_name": bucket_name,
        "policies": policies,
        "users": users,
        "message": message
    })


@app.post("/bucket/{bucket_name}", response_class=HTMLResponse)
async def bucket_post(
    request: Request,
    bucket_name: str,
    action: str = Form(...),
    user: str = Form(None),
    policy: str = Form(None),
    policy_name: str = Form(None)
):
    message = ""

    if action == "detach_policy":
        result = run_mc_command([MC_BINARY, "admin", "policy", "detach", MINIO_ALIAS, policy, "--user", user])
        message = result if "Error" in result else f"Policy '{policy}' von Benutzer '{user}' entfernt."
    elif action == "attach_policy":
        # Bucket-spezifische Policy erstellen falls nötig
        actual_policy = ensure_bucket_policy(bucket_name, policy_name)
        if "Error" in actual_policy:
            message = actual_policy
        else:
            result = run_mc_command([MC_BINARY, "admin", "policy", "attach", MINIO_ALIAS, actual_policy, "--user", user])
            message = result if "Error" in result else f"Policy '{actual_policy}' für Benutzer '{user}' auf Bucket '{bucket_name}' gesetzt."

    request.session["message"] = message
    return RedirectResponse(url=f"/bucket/{bucket_name}", status_code=303)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=9002)
