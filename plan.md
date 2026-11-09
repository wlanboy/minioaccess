# Verbesserungsplan minioaccess

Stand: 2026-11-09. Sortiert nach Priorität. Jeder Punkt nennt Fundstelle, Problem und Maßnahme.

---

## P1 – Sicherheit (vor jedem weiteren Ausbau)

### 1.1 Keine Authentifizierung
- **Problem:** Jeder, der Port 9002 erreicht, hat volle MinIO-Admin-Rechte (User anlegen, Buckets mit `--force` löschen, Policies vergeben). Die App nutzt dafür die Admin-Credentials aus der Umgebung.
- **Maßnahme:**
  - Login-Seite gegen MinIO selbst: Benutzername/Secret per `mc admin info` bzw. STS prüfen, Ergebnis in der Session merken. Alternativ ein festes Admin-Passwort per ENV (`APP_PASSWORD`, gehasht vergleichen mit `secrets.compare_digest`).
  - Oder OIDC/Reverse-Proxy (oauth2-proxy, Authelia) davor; dann in der README dokumentieren, dass der Dienst nie direkt erreichbar sein darf.
  - Session-Secret aus ENV (`SESSION_SECRET`) statt `os.urandom()` beim Start ([main.py:39](main.py#L39)), sonst sind Sessions nach jedem Neustart und bei mehreren Workern ungültig.
  - Cookie mit `https_only=True` und `same_site="strict"` setzen.

### 1.2 Kein CSRF-Schutz
- **Problem:** Alle Aktionen sind einfache Form-POSTs ohne Token. Eine fremde Webseite kann im Browser eines Admins im LAN z. B. `POST /buckets action=delete_bucket` auslösen.
- **Maßnahme:** CSRF-Token pro Session in jedes Formular (Jinja-Macro), in jedem POST-Handler prüfen. Zusätzlich `SameSite=strict` (siehe 1.1).

### 1.3 Policy-Eskalation über den Bucket-Namen im Pfad
- **Fundstelle:** [main.py:166](main.py#L166) `POST /bucket/{bucket_name}` → `ensure_bucket_policy` → [mc_commands.py:106](mc_commands.py#L106)
- **Problem:** `bucket_name` wird weder validiert noch gegen existierende Buckets geprüft. `POST /bucket/*` mit `policy_name=readwrite` erzeugt die Policy `*-readwrite` mit `Resource: arn:aws:s3:::*` und `s3:*`, also Vollzugriff auf alle Buckets für den gewählten User.
- **Maßnahme:**
  - Bucket-Namen zentral gegen die S3-Regeln validieren (`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`, keine `..`, kein IP-Format).
  - Im Detail- und POST-Handler prüfen, dass der Bucket in `list_buckets()` existiert, sonst 404.
  - `policy_name` gegen die erlaubten Typen (`readonly`, `readwrite`, `writeonly`) prüfen, bevor etwas angelegt wird.
- **Status (2026-11-09):** umgesetzt. `is_valid_bucket` in `mc_commands.py` (inkl. IPv4-Prüfung), `GET`/`POST /api/buckets/{name}/policies` liefern 404 für unbekannte Buckets, `DELETE` und Detach validieren ebenfalls.

### 1.4 Argument-Injection in `mc`-Aufrufe
- **Fundstelle:** alle Funktionen in [mc_commands.py](mc_commands.py), die Formularwerte durchreichen
- **Problem:** Werte, die mit `-` beginnen (z. B. Benutzername `--insecure` oder `--help`), interpretiert `mc` als Flags. Bucket-Namen landen ungeprüft in `f"{alias}/{bucket}"`.
- **Maßnahme:** Eingaben validieren (Access-Key: `^[A-Za-z0-9._@=+,-]{3,128}$`, nicht mit `-` beginnend; Bucket siehe 1.3). Wo `mc` es unterstützt, `--` vor Positionsargumente setzen.
- **Status (2026-11-09):** umgesetzt über Validierung in `main.py` (400) und zusätzlich `_check` in jeder `mc_commands`-Funktion mit Benutzereingaben (`ValueError`). Secrets dürfen nicht mit `-` beginnen. `--` nicht eingeführt, weil ungeprüft, welche `mc`-Subcommands es akzeptieren; nach der Validierung beginnt kein Argument mehr mit `-`.

### 1.5 Admin-Secret in Prozessliste und Logs
- **Fundstelle:** [mc_commands.py:59](mc_commands.py#L59) `mc alias set ... MINIO_SECRET_KEY`, [mc_commands.py:29](mc_commands.py#L29) `print(f"MC Command: {result.stdout}")`
- **Problem:** Das Secret steht während des Aufrufs in `/proc/<pid>/cmdline` und landet dauerhaft in `~/.mc/config.json`. Die JSON-Ausgabe von `alias set` enthält je nach `mc`-Version Access- und Secret-Key und wird per `print` ins Container-Log geschrieben (prüfen).
- **Maßnahme:** Alias nicht mehr anlegen, sondern `MC_HOST_<alias>=https://KEY:SECRET@host` nur in der `env` des Subprozesses setzen. `setup_mc_alias` wird dann zu einem Verbindungstest (`mc admin info`). Stdout nicht mehr pauschal loggen (siehe 3.3).
- **Status (2026-11-09):** umgesetzt. `MC_HOST_<alias>` (URL-kodiert) nur in der Subprozess-Umgebung, `setup_mc_alias` → `check_connection` (`mc admin info`), Logging per `logging` (`LOG_LEVEL`) nur mit Aktionsname und Exit-Code. Offen: Beim Anlegen eines Users bzw. Ändern des Passworts steht dessen Secret weiterhin in der Kommandozeile von `mc admin user add`.

### 1.6 Löschen ohne Rückfrage
- **Problem:** `delete_bucket` nutzt `mc rb --force` ([mc_commands.py:235](mc_commands.py#L235)) und löscht den Bucket samt Inhalt nach einem Klick. Gleiches gilt für User und Policies.
- **Maßnahme:** Bestätigung im UI (`onsubmit="return confirm(...)"` oder Eingabe des Namens wie bei GitHub). Option ohne `--force`, die nur leere Buckets löscht, als Default.
- **Status (2026-11-09):** umgesetzt. Bestätigungsdialoge gab es mit dem neuen Frontend schon für User, Buckets, Zuordnungen und Policies. `DELETE /api/buckets/{name}` löscht jetzt ohne `--force` (nur leere Buckets), `?force=true` löscht samt Inhalt. Im Dialog dafür ein Häkchen „Inhalt mitlöschen“, danach muss der Bucket-Name eingetippt werden.

---

## P2 – Fehler und Robustheit

### 2.1 Option „bucket-spezifisch“ funktioniert nicht
- **Fundstelle:** [templates/bucket.html](templates/bucket.html) `<option value="{{ bucket_name }}">`
- **Problem:** Der Wert landet als `policy_type` in `get_policy_actions`, das liefert `[]`, die Aktion endet immer mit „Unbekannter Policy-Typ“.
- **Maßnahme:** Option entfernen oder echte Bedeutung definieren (z. B. Auswahl einer bestehenden Policy aus `list_policies()`).

### 2.2 Fehlererkennung über `"Error" in result`
- **Problem:** Erfolg/Fehler wird per Substring erkannt ([main.py](main.py), `ensure_bucket_policy`, `create_bucket_policy`). Ein Benutzer- oder Policy-Name mit „Error“ im Text verfälscht das Ergebnis.
- **Maßnahme:** `run_mc_command` gibt ein Ergebnisobjekt zurück (`@dataclass McResult(ok: bool, output: str, error: str | None)`) oder wirft `McError`. Handler prüfen `ok`.

### 2.3 MinIO nicht erreichbar = „Keine Benutzer vorhanden“
- **Problem:** `list_users`, `list_buckets`, `list_policies` liefern bei Fehlern `[]`. Die Seite zeigt dann eine leere Liste statt eines Fehlers.
- **Maßnahme:** Fehler an den Handler durchreichen und als Fehlermeldung anzeigen.

### 2.4 Kein Timeout für `mc`
- **Fundstelle:** [mc_commands.py:28](mc_commands.py#L28)
- **Problem:** Hängt MinIO, hängt der Request unbegrenzt.
- **Maßnahme:** `subprocess.run(..., timeout=MC_TIMEOUT)` (Default 15 s), `TimeoutExpired` als Fehler melden.

### 2.5 `writeonly` reicht nicht für große Uploads
- **Fundstelle:** [mc_commands.py:97](mc_commands.py#L97)
- **Problem:** Nur `s3:PutObject`. Multipart-Uploads brauchen zusätzlich `s3:AbortMultipartUpload`, `s3:ListMultipartUploadParts`, `s3:ListBucketMultipartUploads`.
- **Maßnahme:** Actions ergänzen. Bei `readonly` die Bucket-Actions (`ListBucket`, `GetBucketLocation`) nur auf `arn:aws:s3:::bucket` und `GetObject` nur auf `bucket/*` legen (sauberere Policy, gleiche Wirkung).

### 2.6 `MC_BINARY = "./mc"` hängt vom Arbeitsverzeichnis ab
- **Maßnahme:** Per ENV konfigurierbar (`MC_BINARY`), Fallback `shutil.which("mc")`, beim Start prüfen, ob die Datei ausführbar ist.

---

## P3 – Performance und Code-Struktur

### 3.1 Blockierende Subprozesse im Event-Loop
- **Problem:** Alle Handler sind `async def`, rufen aber synchron `subprocess.run` auf. Ein langsamer `mc`-Aufruf blockiert alle anderen Requests.
- **Maßnahme:** Handler auf `def` umstellen (FastAPI führt sie dann im Threadpool aus). Minimaler Umbau, keine Logikänderung.

### 3.2 N+1 `mc`-Aufrufe
- **Fundstelle:** `get_bucket_policies` (ein `admin user info` pro User), `/policies` (ein `admin policy info` pro Policy)
- **Maßnahme:** Prüfen, ob `mc --json admin user list` bereits `policyName` liefert, dann entfällt die Schleife. Für die Zuordnung Policy → User gibt es `mc admin policy entities`. Für `/policies` alternativ parallel über einen `ThreadPoolExecutor`.

### 3.3 `print` statt `logging`
- **Maßnahme:** `logging` mit Level per ENV, Kommando ohne Secrets loggen (Name der Aktion, Exit-Code, Dauer), Stdout nur auf DEBUG.

### 3.4 Wiederholte Handler-Logik
- **Problem:** Jeder `elif`-Zweig in [main.py](main.py) wiederholt „Name prüfen → Funktion aufrufen → Meldung bauen“.
- **Maßnahme:** Tabelle `action → (validator, funktion, erfolgsmeldung)` oder getrennte Routen (`POST /users/{name}/disable` usw.). Getrennte Routen machen auch Tests und CSRF-Prüfung einfacher.

### 3.5 Konfiguration beim Import
- **Problem:** `_require_env` läuft beim Import von `mc_commands`. Tests brauchen dafür `conftest.py` mit Dummy-Werten.
- **Maßnahme:** `Settings`-Objekt (pydantic-settings oder Dataclass), das im `lifespan` geladen wird.

### 3.6 Abhängigkeiten
- `dotenv` ist ein Wrapper-Paket; direkt `python-dotenv` eintragen.
- `pyproject.toml`: `description` ist noch „Add your description here“.

---

## P4 – Tests

- Route-Tests mit `fastapi.testclient.TestClient` und gemocktem `run_mc_command`: Validierung (leere Namen, zu kurze Secrets, ungültige Bucket-Namen, `*`), Redirect 303, Flash-Meldung.
- Tests für `run_mc_command` selbst: Exit-Code ≠ 0 mit JSON-Fehler, mit Text-Fehler, `OSError`, Timeout.
- Regressionstests für 1.3 (`/bucket/*`) und 2.1.
- Optional: Integrationstest gegen einen MinIO-Container (Service-Container in GitHub Actions).

---

## P5 – UI

- Mehrfach kopierter Meldungsblock in allen Templates → Jinja-Macro in `base.html`.
- `templates/index.html` wird nicht mehr verwendet (`/` leitet auf `/users` um) → löschen.
- „Benutzer löschen“ per Freitextfeld → Löschen-Button in der Tabellenzeile wie bei Buckets.
- Bucket-Detailseite: zusätzlich anzeigen, welche User die Policy bereits haben, und doppeltes Zuweisen verhindern.
- Dark-Mode-Zustand in `localStorage` speichern.
- Aktiven Navigationspunkt markieren.

---

## P6 – Docker und CI

### 6.1 Dockerfile
- `mc` wird ungepinnt und ohne Prüfsumme von `dl.min.io` geladen und ist fest `linux-amd64`. → Version per `ARG MC_VERSION` pinnen, `sha256sum -c` gegen die veröffentlichte `.sha256sum`, Architektur über `ARG TARGETARCH`.
- `RUN chown -R appuser:appuser /app` erzeugt eine zusätzliche Layer-Kopie aller Dateien → `COPY --chown=appuser:appuser` und den `RUN` entfernen. Der App-Code muss nicht dem App-User gehören; nur `~/.mc` braucht Schreibrechte (entfällt mit 1.5 ganz).
- Abhängigkeiten aus `uv.lock` installieren (`uv sync --frozen --no-dev` im Builder, `.venv` kopieren) statt aus der separat gepflegten `requirements.txt`. Cache-Mount für den uv-Cache.
- `HEALTHCHECK` bzw. Endpoint `/healthz` (Prozess lebt) und `/readyz` (`mc admin info` erfolgreich) für Kubernetes-Probes.
- OCI-Labels (`title`, `version`, `source`, `licenses`, `base.name`) setzen, `version` synchron mit `pyproject.toml`.
- `uvicorn --proxy-headers` falls hinter Reverse-Proxy betrieben.
- `getclient.sh`: Shebang und Architektur-Erkennung ergänzen.

### 6.2 Workflows
- `docker-publish-minioweb.yml`: pusht nur `latest`. → Zusätzlich Tag aus Git-Tag/Version, Multi-Arch über `docker/build-push-action` mit `platforms: linux/amd64,linux/arm64`, GHA-Build-Cache.
- `docker/login-action@v4` per Commit-SHA pinnen wie die übrigen Actions.
- `ci.yaml`: `permissions: contents: read` ergänzen. Optional `docker build` als Smoke-Test.
- Image-Scan (Trivy) im Publish-Workflow.

### 6.3 README
- README nennt das Image `wlanboy/minioweb`, gepusht wird `wlanboy/minioaccess` → vereinheitlichen.
- Abschnitt zu Authentifizierung/Betrieb hinter Proxy ergänzen, sobald 1.1 umgesetzt ist.

---

## Vorgeschlagene Reihenfolge

1. 1.3, 1.4, 2.1, 2.4, 3.1 – kleine Änderungen, schließen die akuten Lücken (jeweils mit Test).
2. 1.5, 2.2, 2.3, 3.3 – `run_mc_command` umbauen (Ergebnisobjekt, `MC_HOST_*`, Logging, Timeout).
3. 1.1, 1.2, 1.6 – Login, CSRF, Bestätigungen.
4. P4 Tests vervollständigen, danach 3.4/3.5 Refactoring.
5. P6 Docker/CI, P5 UI.

Längerfristig zu prüfen: Ersatz des `mc`-Binaries durch die Admin-API der Python-Bibliothek `minio` (`MinioAdmin`). Damit entfallen Subprozesse, Binary-Download und das Parsen von NDJSON.
