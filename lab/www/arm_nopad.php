<?php
error_reporting(E_ALL);
ini_set("display_errors", "1");

if (isset($_GET["arm"])) {
    // No pad — rely on the serialized HUGE string alone to trip memory_limit
    $payload = file_get_contents("/tmp/arm_nopad.ser");
    @unserialize($payload);
    echo "unreachable\n";
    exit;
}
echo "idle\n";
