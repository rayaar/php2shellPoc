<?php
error_reporting(E_ALL);
ini_set("display_errors", "1");

if (isset($_GET["probe"])) {
    // Simple unserialize of a valid serialized int
    $result = unserialize('i:42;');
    echo "probe_result: ", var_export($result, true), "\n";
    exit;
}
echo "idle\n";
