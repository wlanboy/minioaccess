# Build Stage
FROM python:3.15-slim AS builder

# mc wird seit dem Archivieren des Projekts nicht mehr von dl.min.io ausgeliefert (410 Gone).
# Quelle sind die GitHub-Releases von minio/mc. Die Prüfsummen stammen aus den dort
# veröffentlichten .sha256sum-Dateien und sind hier fest eingetragen, damit ein
# ausgetauschtes Binary den Build bricht.
ARG MC_VERSION=RELEASE.2025-08-13T08-35-41Z
ARG MC_SHA256_AMD64=01f866e9c5f9b87c2b09116fa5d7c06695b106242d829a8bb32990c00312e891
ARG MC_SHA256_ARM64=14c8c9616cfce4636add161304353244e8de383b2e2752c0e9dad01d4c27c12c
# Von BuildKit gesetzt (amd64/arm64), bei --platform entsprechend
ARG TARGETARCH

WORKDIR /app

# MC client herunterladen und prüfen (Python statt curl, spart apt-get)
RUN case "${TARGETARCH:-amd64}" in \
      amd64) MC_SHA256="$MC_SHA256_AMD64" ;; \
      arm64) MC_SHA256="$MC_SHA256_ARM64" ;; \
      *) echo "Nicht unterstützte Architektur: $TARGETARCH" >&2; exit 1 ;; \
    esac \
    && python -c "import sys, urllib.request; urllib.request.urlretrieve(sys.argv[1], '/app/mc')" \
       "https://github.com/minio/mc/releases/download/${MC_VERSION}/mc.linux-${TARGETARCH:-amd64}.${MC_VERSION}" \
    && echo "${MC_SHA256}  /app/mc" | sha256sum -c - \
    && chmod 0755 /app/mc

# Python-Abhängigkeiten installieren
COPY requirements.txt requirements.txt
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt


# Runtime Stage
FROM python:3.15-slim

LABEL org.opencontainers.image.title="minioaccess" \
      org.opencontainers.image.description="Web-Oberfläche zur Verwaltung von MinIO-Benutzern, Buckets und Policies über den mc-Client" \
      org.opencontainers.image.version="0.1.0" \
      org.opencontainers.image.vendor="wlanboy" \
      org.opencontainers.image.source="https://github.com/wlanboy/minioaccess" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.base.name="python:3.15-slim"

WORKDIR /app

# Non-root User. Das Home-Verzeichnis braucht mc für ~/.mc (legt es beim Start an).
RUN useradd --create-home --shell /usr/sbin/nologin appuser

# Python-Pakete aus dem Build-Stage kopieren
COPY --from=builder /install /usr/local

# mc und Anwendungscode gehören root: der App-User muss sie nur lesen und ausführen
COPY --from=builder /app/mc /app/mc
COPY main.py mc_commands.py /app/
COPY static/ /app/static/

# Auf non-root User wechseln
USER appuser

# Absoluter Pfad, unabhängig vom Arbeitsverzeichnis
ENV MC_BINARY=/app/mc

EXPOSE 9002

# Liveness ohne mc-Aufruf. Readiness (/readyz, prüft MinIO) gehört in die Kubernetes-Probe.
HEALTHCHECK --interval=30s --timeout=3s --start-period=20s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:9002/healthz', timeout=2)"]

# Uvicorn starten
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "9002"]
