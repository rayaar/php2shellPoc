<?php
error_reporting(E_ALL);
ini_set("display_errors", "1");

if (isset($_GET["arm7"])) {
    // Pre-fill some memory to tighten budget
    $pad = str_repeat("B", 4 * 1024 * 1024);  // 4MB
    $payload = file_get_contents("/tmp/arm7.ser");  // ~3MB
    // Now unserialize: object first (populates dtor), then huge string OOMs
    @unserialize($payload);
    echo "arm7_unreachable\n";
    exit;
}
echo "idle\n";
