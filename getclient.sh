#!/bin/sh
# Lädt den MinIO-Client (mc) für lokale Entwicklung nach ./mc und prüft die Prüfsumme.
# dl.min.io liefert mc nicht mehr aus (410 Gone), Quelle sind die GitHub-Releases.
# Version und Prüfsummen synchron zum Dockerfile halten.
set -eu

MC_VERSION="${MC_VERSION:-RELEASE.2025-08-13T08-35-41Z}"

case "$(uname -s)" in
  Linux) os=linux ;;
  Darwin) os=darwin ;;
  *) echo "Nicht unterstütztes Betriebssystem: $(uname -s)" >&2; exit 1 ;;
esac

case "$(uname -m)" in
  x86_64|amd64) arch=amd64 ;;
  aarch64|arm64) arch=arm64 ;;
  *) echo "Nicht unterstützte Architektur: $(uname -m)" >&2; exit 1 ;;
esac

# Linux-Prüfsummen fest eingetragen (wie im Dockerfile), sonst die veröffentlichte .sha256sum
case "$os-$arch-$MC_VERSION" in
  linux-amd64-RELEASE.2025-08-13T08-35-41Z) sha256=01f866e9c5f9b87c2b09116fa5d7c06695b106242d829a8bb32990c00312e891 ;;
  linux-arm64-RELEASE.2025-08-13T08-35-41Z) sha256=14c8c9616cfce4636add161304353244e8de383b2e2752c0e9dad01d4c27c12c ;;
  *) sha256="" ;;
esac

url="https://github.com/minio/mc/releases/download/${MC_VERSION}/mc.${os}-${arch}.${MC_VERSION}"
if [ -z "$sha256" ]; then
  sha256=$(curl -fsSL "${url}.sha256sum" | cut -d' ' -f1)
fi

echo "Lade mc ${MC_VERSION} (${os}-${arch})"
curl -fsSL -o mc.tmp "$url"

if command -v sha256sum >/dev/null 2>&1; then
  actual=$(sha256sum mc.tmp | cut -d' ' -f1)
else
  actual=$(shasum -a 256 mc.tmp | cut -d' ' -f1)
fi
if [ "$actual" != "$sha256" ]; then
  rm -f mc.tmp
  echo "Prüfsumme falsch: erwartet $sha256, erhalten $actual" >&2
  exit 1
fi

chmod +x mc.tmp
mv mc.tmp mc
./mc --version | head -1
