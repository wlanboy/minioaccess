import logging
import os
from contextlib import asynccontextmanager
from urllib.parse import urlsplit

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from mc_commands import (
    POLICY_TYPES,
    attach_policy,
    change_password,
    check_connection,
    create_bucket,
    create_user,
    delete_bucket,
    delete_policy,
    delete_user,
    detach_policy,
    disable_user,
    enable_user,
    ensure_bucket_policy,
    get_bucket_policies,
    get_policy_details,
    is_valid_access_key,
    is_valid_bucket,
    is_valid_policy_name,
    is_valid_secret,
    list_buckets,
    list_policies,
    list_users,
)

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO").upper())

MIN_SECRET_LENGTH = 12


@asynccontextmanager
async def lifespan(_app: FastAPI):
    check_connection()
    yield


app = FastAPI(lifespan=lifespan)


# ---------------------------------------------------------------------------
# CSRF-Schutz
# ---------------------------------------------------------------------------
# Schreibende API-Aufrufe brauchen den Header X-Requested-With. Einen eigenen
# Header kann eine fremde Seite nur nach einem CORS-Preflight setzen, und den
# beantwortet die App nicht (keine CORS-Middleware). Formular-POSTs und
# no-cors-fetch() von fremden Seiten scheitern damit. Sec-Fetch-Site und Origin
# werden zusätzlich geprüft, falls der Browser sie mitschickt.

CSRF_HEADER = "x-requested-with"
CSRF_VALUE = "minioaccess"
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


def _csrf_violation(request: Request) -> str | None:
    if request.headers.get(CSRF_HEADER) != CSRF_VALUE:
        return "CSRF-Header fehlt."
    fetch_site = request.headers.get("sec-fetch-site")
    if fetch_site and fetch_site not in ("same-origin", "none"):
        return f"Cross-Site-Anfrage abgelehnt ({fetch_site})."
    origin = request.headers.get("origin")
    if origin and urlsplit(origin).netloc != request.headers.get("host"):
        return "Origin passt nicht zum Host."
    return None


@app.middleware("http")
async def csrf_protect(request: Request, call_next):
    if request.method not in SAFE_METHODS and request.url.path.startswith("/api/"):
        violation = _csrf_violation(request)
        if violation:
            return JSONResponse({"detail": f"Fehler: {violation}"}, status_code=403)
    return await call_next(request)


# ---------------------------------------------------------------------------
# Request-Modelle
# ---------------------------------------------------------------------------

class UserCreate(BaseModel):
    access_key: str
    secret_key: str


class PasswordChange(BaseModel):
    secret_key: str


class BucketCreate(BaseModel):
    name: str


class PolicyAttach(BaseModel):
    user: str
    policy_type: str


# ---------------------------------------------------------------------------
# Hilfsfunktionen
# ---------------------------------------------------------------------------

def _fail(message: str):
    raise HTTPException(status_code=400, detail=message)


def _result(result: str, success: str) -> dict:
    """Wandelt die Ausgabe eines mc-Aufrufs in eine API-Antwort um."""
    if "Error" in result:
        _fail(result)
    return {"message": success}


def _require_name(value: str, label: str) -> str:
    value = value.strip()
    if not value:
        _fail(f"Fehler: {label} darf nicht leer sein.")
    return value


def _require_bucket(value: str) -> str:
    value = _require_name(value, "Bucket-Name")
    if not is_valid_bucket(value):
        _fail(f"Fehler: Ungültiger Bucket-Name '{value}'.")
    return value


def _require_existing_bucket(value: str) -> str:
    value = _require_bucket(value)
    if value not in list_buckets():
        raise HTTPException(status_code=404, detail=f"Fehler: Bucket '{value}' existiert nicht.")
    return value


def _require_user(value: str) -> str:
    value = _require_name(value, "Benutzername")
    if not is_valid_access_key(value):
        _fail(
            f"Fehler: Ungültiger Benutzername '{value}' (3–128 Zeichen aus A–Z, a–z, 0–9 und ._@=+,-, "
            "nicht mit '-' beginnend)."
        )
    return value


def _require_policy(value: str) -> str:
    value = _require_name(value, "Policy-Name")
    if not is_valid_policy_name(value):
        _fail(f"Fehler: Ungültiger Policy-Name '{value}'.")
    return value


def _require_secret(secret: str, label: str):
    if len(secret) < MIN_SECRET_LENGTH:
        _fail(f"Fehler: {label} muss mindestens {MIN_SECRET_LENGTH} Zeichen lang sein.")
    if not is_valid_secret(secret):
        _fail(f"Fehler: {label} darf nicht mit '-' beginnen.")


# Die Endpunkte sind bewusst synchron (def statt async def): mc läuft per
# subprocess und blockiert, FastAPI führt sie deshalb im Threadpool aus.

# ---------------------------------------------------------------------------
# Users
# ---------------------------------------------------------------------------

@app.get("/api/users")
def users_list():
    return list_users()


@app.post("/api/users")
def users_create(body: UserCreate):
    name = _require_user(body.access_key)
    _require_secret(body.secret_key, "Das Secret")
    return _result(create_user(name, body.secret_key), f"Benutzer '{name}' erstellt.")


@app.delete("/api/users/{name}")
def users_delete(name: str):
    name = _require_user(name)
    return _result(delete_user(name), f"Benutzer '{name}' gelöscht.")


@app.put("/api/users/{name}/password")
def users_password(name: str, body: PasswordChange):
    name = _require_user(name)
    _require_secret(body.secret_key, "Das neue Passwort")
    return _result(change_password(name, body.secret_key), f"Passwort für Benutzer '{name}' geändert.")


@app.post("/api/users/{name}/enable")
def users_enable(name: str):
    name = _require_user(name)
    return _result(enable_user(name), f"Benutzer '{name}' aktiviert.")


@app.post("/api/users/{name}/disable")
def users_disable(name: str):
    name = _require_user(name)
    return _result(disable_user(name), f"Benutzer '{name}' deaktiviert.")


# ---------------------------------------------------------------------------
# Buckets
# ---------------------------------------------------------------------------

@app.get("/api/buckets")
def buckets_list():
    return list_buckets()


@app.post("/api/buckets")
def buckets_create(body: BucketCreate):
    name = _require_bucket(body.name)
    return _result(create_bucket(name), f"Bucket '{name}' erstellt.")


@app.delete("/api/buckets/{name}")
def buckets_delete(name: str):
    name = _require_bucket(name)
    return _result(delete_bucket(name), f"Bucket '{name}' gelöscht.")


@app.get("/api/buckets/{name}/policies")
def bucket_policies(name: str):
    return get_bucket_policies(_require_existing_bucket(name))


@app.post("/api/buckets/{name}/policies")
def bucket_policy_attach(name: str, body: PolicyAttach):
    name = _require_existing_bucket(name)
    user = _require_user(body.user)
    if body.policy_type not in POLICY_TYPES:
        _fail(f"Fehler: Unbekannter Policy-Typ '{body.policy_type}'.")
    policy = ensure_bucket_policy(name, body.policy_type)
    if "Error" in policy:
        _fail(policy)
    return _result(
        attach_policy(policy, user),
        f"Policy '{policy}' für Benutzer '{user}' auf Bucket '{name}' gesetzt.",
    )


@app.delete("/api/buckets/{name}/policies/{policy}/users/{user}")
def bucket_policy_detach(name: str, policy: str, user: str):
    _require_bucket(name)
    policy = _require_policy(policy)
    user = _require_user(user)
    return _result(detach_policy(policy, user), f"Policy '{policy}' von Benutzer '{user}' entfernt.")


# ---------------------------------------------------------------------------
# Policies
# ---------------------------------------------------------------------------

@app.get("/api/policies")
def policies_list():
    return [get_policy_details(name) for name in list_policies()]


@app.delete("/api/policies/{name}")
def policies_delete(name: str):
    name = _require_policy(name)
    return _result(delete_policy(name), f"Policy '{name}' gelöscht.")


# Statisches Frontend zuletzt einhängen, damit /api/* Vorrang hat.
app.mount("/", StaticFiles(directory="static", html=True), name="static")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=9002)
