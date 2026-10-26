<?php
error_reporting(E_ALL);
ini_set("display_errors", "1");

if (isset($_GET["arm4"])) {
    // Pre-fill memory, then unserialize a string that pushes over the limit
    // 8M limit; 6M pre-fill leaves ~2M; try to unserialize a 3M string
    $pad = str_repeat("B", 6 * 1024 * 1024);
    $N = 3 * 1024 * 1024;
    $payload = 's:' . $N . ':"' . str_repeat("A", $N) . '";';
    @unserialize($payload);  // OOM during string alloc inside unserialize parse
    echo "arm4_unreachable\n";
    exit;
}

echo "idle\n";
