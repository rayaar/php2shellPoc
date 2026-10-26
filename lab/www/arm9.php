<?php
error_reporting(E_ALL);
ini_set("display_errors", "1");
if (isset($_GET["arm9"])) {
    $pad = str_repeat("B", 2 * 1024 * 1024);
    $payload = file_get_contents("/tmp/arm9.ser");
    @unserialize($payload);
    echo "arm9_unreachable\n";
    exit;
}
echo "idle\n";
