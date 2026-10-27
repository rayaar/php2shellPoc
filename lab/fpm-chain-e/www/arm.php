<?php
// Arm endpoint: triggers session_start() from application code so the OOM
// mid-decode is "in-band" (fatal rendered in response, child survives, BG
// state left dangling across the request boundary).
session_start();
echo "unreachable (session_start should have OOM'd on a huge planted file)\n";
