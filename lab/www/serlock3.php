<?php
error_reporting(E_ALL);
ini_set("display_errors", "1");

if (isset($_GET["arm3"])) {
    // Build a crafted serialized string: huge array that will OOM during insert
    // a:LARGE:{ ... }   -- PHP preallocates HashTable for `LARGE` elements
    // The payload: an array claim of 100 million elements
    $payload = 'a:' . (100 * 1000 * 1000) . ':{}';
    @unserialize($payload);
    echo "arm3_unreachable\n";
    exit;
}

echo "idle\n";
