import os
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from mc_commands import (
    setup_mc_alias,
    list_users,
    list_buckets,
    list_policies,
    get_policy_details,
    delete_policy,
    get_bucket_policies,
    ensure_bucket_policy,
    create_user,
    delete_user,
    change_password,
    enable_user,
    disable_user,
    create_bucket,
    delete_bucket,
    attach_policy,
    detach_policy,
)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    setup_mc_alias()
    yield


app = FastAPI(lifespan=lifespan)
app.add_middleware(SessionMiddleware, secret_key=os.urandom(24).hex())
app.mount("/static", StaticFiles(directory="static"), name="static")

templates = Jinja2Templates(directory="templates")


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
            result = create_user(access_key.strip(), secret_key)
            message = result if "Error" in result else f"Benutzer '{access_key.strip()}' erstellt."
    elif action == "delete_user":
        if not access_key or not access_key.strip():
            message = "Fehler: Benutzername darf nicht leer sein."
        else:
            result = delete_user(access_key.strip())
            message = result if "Error" in result else f"Benutzer '{access_key.strip()}' gelöscht."
    elif action == "change_password":
        if not access_key or not access_key.strip():
            message = "Fehler: Benutzername darf nicht leer sein."
        elif not secret_key or len(secret_key) < 12:
            message = "Fehler: Das neue Passwort muss mindestens 12 Zeichen lang sein."
        else:
            result = change_password(access_key.strip(), secret_key)
            message = result if "Error" in result else f"Passwort für Benutzer '{access_key.strip()}' geändert."
    elif action == "enable_user":
        if not access_key or not access_key.strip():
            message = "Fehler: Benutzername darf nicht leer sein."
        else:
            result = enable_user(access_key.strip())
            message = result if "Error" in result else f"Benutzer '{access_key.strip()}' aktiviert."
    elif action == "disable_user":
        if not access_key or not access_key.strip():
            message = "Fehler: Benutzername darf nicht leer sein."
        else:
            result = disable_user(access_key.strip())
            message = result if "Error" in result else f"Benutzer '{access_key.strip()}' deaktiviert."

    # Bucket-Verwaltung
    elif action == "create_bucket":
        if not bucket_name or not bucket_name.strip():
            message = "Fehler: Bucket-Name darf nicht leer sein."
        else:
            result = create_bucket(bucket_name.strip())
            message = result if "Error" in result else f"Bucket '{bucket_name.strip()}' erstellt."
    elif action == "delete_bucket":
        if not bucket_name or not bucket_name.strip():
            message = "Fehler: Bucket-Name darf nicht leer sein."
        else:
            result = delete_bucket(bucket_name.strip())
            message = result if "Error" in result else f"Bucket '{bucket_name.strip()}' gelöscht."

    # Policy-Verwaltung
    elif action == "set_policy":
        result = attach_policy(policy_name, policy_user)
        message = result if "Error" in result else f"Policy '{policy_name}' für Benutzer '{policy_user}' gesetzt."

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
        result = detach_policy(policy, user)
        message = result if "Error" in result else f"Policy '{policy}' von Benutzer '{user}' entfernt."
    elif action == "attach_policy":
        # Bucket-spezifische Policy erstellen falls nötig
        actual_policy = ensure_bucket_policy(bucket_name, policy_name)
        if "Error" in actual_policy:
            message = actual_policy
        else:
            result = attach_policy(actual_policy, user)
            message = result if "Error" in result else f"Policy '{actual_policy}' für Benutzer '{user}' auf Bucket '{bucket_name}' gesetzt."

    request.session["message"] = message
    return RedirectResponse(url=f"/bucket/{bucket_name}", status_code=303)


@app.get("/policies", response_class=HTMLResponse)
async def policies_get(request: Request):
    message = request.session.pop("message", None)
    policy_names = list_policies()
    policies = [get_policy_details(name) for name in policy_names]
    return templates.TemplateResponse("policies.html", {
        "request": request,
        "policies": policies,
        "message": message
    })


@app.post("/policies", response_class=HTMLResponse)
async def policies_post(
    request: Request,
    action: str = Form(...),
    policy_name: str = Form(None)
):
    message = ""
    if action == "delete_policy":
        if not policy_name or not policy_name.strip():
            message = "Fehler: Policy-Name darf nicht leer sein."
        else:
            result = delete_policy(policy_name.strip())
            message = result if "Error" in result else f"Policy '{policy_name.strip()}' gelöscht."
    request.session["message"] = message
    return RedirectResponse(url="/policies", status_code=303)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=9002)
