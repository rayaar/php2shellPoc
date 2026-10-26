<?php
error_reporting(E_ALL);
ini_set("display_errors", "1");

if (isset($_GET["arm5"])) {
    // Pre-fill ~5MB, then read payload file (2MB), then unserialize (needs 2MB more)
    $pad = str_repeat("B", 5 * 1024 * 1024);
    $payload = file_get_contents("/tmp/payload.ser");  // 2MB
    @unserialize($payload);  // tries to alloc 2MB zend_string → OOM
    echo "arm5_unreachable\n";
    exit;
}

echo "idle\n";
