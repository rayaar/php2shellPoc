<?php
error_reporting(E_ALL);
ini_set("display_errors", "1");

if (isset($_GET["arm6"])) {
    $pad = str_repeat("B", 3 * 1024 * 1024);   // 3MB
    $payload = file_get_contents("/tmp/payload.ser");  // +2MB = 5MB
    // Now unserialize needs to allocate another 2MB zend_string for the result
    // 5MB + 2MB = 7MB, close but might not trip... let me check
    @unserialize($payload);
    echo "arm6_unreachable\n";
    exit;
}
echo "idle\n";
