#!/usr/bin/env bash
set -euo pipefail

# Igual que arrancar-2h.sh pero con Podman.
# `podman compose` delega en podman-compose o docker-compose (hay que tener uno instalado).
cd "$(dirname "$0")/.."

# inventario.sh y compañía llaman a `docker`: se redirige a podman sin tocarlos.
docker() { podman "$@"; }
export -f docker

NODE_IMAGE="goys-vuln-lab-node:${NODE_TAG:-22.23.3-bookworm-slim}"

if ! podman image exists "$NODE_IMAGE"; then
  echo "Imágenes no encontradas: construyendo (puede tardar unos minutos)..."
  podman compose --env-file versions.env build
fi

podman compose --env-file versions.env up -d

# ponytail: podman-compose no soporta `--wait`, se espera el healthcheck a mano (2 min máx).
for c in php-lab node-lab py-lab; do
  for _ in $(seq 60); do
    [ "$(podman inspect -f '{{.State.Health.Status}}' "$c")" = healthy ] && continue 2
    sleep 2
  done
  echo "$c no llegó a healthy" >&2; exit 1
done

podman ps
echo
./scripts/inventario.sh
