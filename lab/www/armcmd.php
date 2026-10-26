<?php
error_reporting(E_ALL);
ini_set("display_errors", "1");
if (isset($_GET["armcmd"])) {
    $pad = str_repeat("B", 2 * 1024 * 1024);
    // The CMD string will be saved in dtor_entries via duplicate-key override
    $payload = file_get_contents("/tmp/armcmd.ser");
    @unserialize($payload);
    echo "armcmd_unreachable\n";
    exit;
}
echo "idle\n";
