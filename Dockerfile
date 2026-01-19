# Build Stage
FROM python:3.12-slim AS builder

WORKDIR /app

# MC client herunterladen
RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && curl -o /app/mc https://dl.min.io/client/mc/release/linux-amd64/mc \
    && chmod +x /app/mc \
    && apt-get purge -y curl \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*

# Python-Abhängigkeiten installieren
COPY requirements.txt requirements.txt
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt


# Runtime Stage
FROM python:3.12-slim

WORKDIR /app

# Non-root User erstellen
RUN useradd --create-home --shell /bin/bash appuser

# Python-Pakete aus dem Build-Stage kopieren
COPY --from=builder /install /usr/local

# MC Binary aus dem Build-Stage kopieren
COPY --from=builder /app/mc /app/mc

# Anwendungscode kopieren
COPY .env /app/
COPY main.py /app/
COPY templates/ /app/templates/
COPY static/ /app/static/

# Berechtigungen für appuser setzen
RUN chown -R appuser:appuser /app

# Auf non-root User wechseln
USER appuser

EXPOSE 9002

# Uvicorn starten
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "9002"]
