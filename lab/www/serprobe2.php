<?php
error_reporting(E_ALL);
ini_set("display_errors", "1");

if (isset($_GET["probe2"])) {
    // References need var_hash entries. Serialize/unserialize a simple array
    // that uses R: references to prior entries
    $x = 123;
    $arr = [&$x, &$x, &$x];  // 3 entries, all referencing $x
    $ser = serialize($arr);
    echo "serialized: $ser\n";
    $out = @unserialize($ser);
    echo "probe2_result: ", var_export($out, true), "\n";
    exit;
}

if (isset($_GET["probe3"])) {
    // Try unserializing an object — exercises more var_hash fields (allowed_classes etc)
    $obj = @unserialize('O:8:"stdClass":1:{s:3:"foo";i:42;}');
    echo "probe3_result: ", var_export($obj, true), "\n";
    exit;
}

if (isset($_GET["probe4"])) {
    // Direct reference exercise
    $ser = 'a:2:{i:0;i:42;i:1;R:2;}';  // array where element 1 is a reference to element 0
    $out = @unserialize($ser);
    echo "probe4_result: ", var_export($out, true), "\n";
    exit;
}

echo "idle\n";
