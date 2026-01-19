import os
import subprocess
from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
from dotenv import load_dotenv

load_dotenv()

app = FastAPI()
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

    users = []
    for line in output.split('\n'):
        parts = line.split()
        if len(parts) >= 2:
            users.append(parts[1])
    return users


def list_buckets():
    output = run_mc_command([MC_BINARY, "ls", MINIO_ALIAS])
    return [line.strip().split()[-1] for line in output.split('\n') if line.strip() and not line.startswith("mc: <") and not line.startswith("mc: ERROR")]


def get_bucket_policies(bucket: str):
    """Holt alle User-Policy-Zuordnungen für ein Bucket."""
    policies = []

    # Liste alle Policies
    output = run_mc_command([MC_BINARY, "admin", "policy", "list", MINIO_ALIAS])
    if "Error" in output:
        return policies

    policy_names = [line.strip() for line in output.split('\n') if line.strip()]

    # Für jede Policy prüfen, welche User zugeordnet sind
    for policy_name in policy_names:
        # Policy-Details abrufen (zeigt zugeordnete User)
        info_output = run_mc_command([MC_BINARY, "admin", "policy", "info", MINIO_ALIAS, policy_name])
        if "Error" not in info_output:
            # Parse die User aus der Policy-Info
            for line in info_output.split('\n'):
                if "User:" in line or "user:" in line.lower():
                    user = line.split(":")[-1].strip()
                    if user:
                        policies.append({
                            "user": user,
                            "policy": policy_name
                        })

    # Alternative: Alle User durchgehen und deren Policies prüfen
    users = list_users()
    policies = []
    for user in users:
        user_info = run_mc_command([MC_BINARY, "admin", "user", "info", MINIO_ALIAS, user])
        if "Error" not in user_info:
            for line in user_info.split('\n'):
                if "PolicyName:" in line or "Policy:" in line:
                    policy = line.split(":")[-1].strip()
                    if policy and (bucket in policy or policy in ["readonly", "readwrite", "writeonly", "diagnostics"]):
                        policies.append({
                            "user": user,
                            "policy": policy
                        })

    return policies


@app.on_event("startup")
async def startup_event():
    setup_mc_alias()


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
    policy_bucket: str = Form(None),
    policy_name: str = Form(None)
):
    message = ""

    # Benutzerverwaltung
    if action == "create_user":
        user = access_key
        secret = secret_key

        if not secret or len(secret) < 12:
            message = "Fehler: Das Secret muss mindestens 12 Zeichen lang sein."
        else:
            result = run_mc_command([MC_BINARY, "admin", "user", "add", MINIO_ALIAS, user, secret])
            message = result if "Error" in result else f"Benutzer '{user}' erstellt."
    elif action == "delete_user":
        user = access_key
        result = run_mc_command([MC_BINARY, "admin", "user", "remove", MINIO_ALIAS, user])
        message = result if "Error" in result else f"Benutzer '{user}' gelöscht."

    # Bucket-Verwaltung
    elif action == "create_bucket":
        bucket = bucket_name
        result = run_mc_command([MC_BINARY, "mb", f"{MINIO_ALIAS}/{bucket}"])
        message = result if "Error" in result else f"Bucket '{bucket}' erstellt."
    elif action == "delete_bucket":
        bucket = bucket_name
        result = run_mc_command([MC_BINARY, "rb", "--force", f"{MINIO_ALIAS}/{bucket}"])
        message = result if "Error" in result else f"Bucket '{bucket}' gelöscht."

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
        result = run_mc_command([MC_BINARY, "admin", "policy", "attach", MINIO_ALIAS, policy_name, "--user", user])
        message = result if "Error" in result else f"Policy '{policy_name}' für Benutzer '{user}' gesetzt."

    request.session["message"] = message
    return RedirectResponse(url=f"/bucket/{bucket_name}", status_code=303)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
