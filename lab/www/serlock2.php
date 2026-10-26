<?php
error_reporting(E_ALL);
ini_set("display_errors", "1");

if (isset($_GET["arm2"])) {
    // Trigger OOM during the main unserialize parse (not inside __wakeup)
    // s:N: tries to allocate N bytes for a string.
    // Build serialized: a large string literal that forces 10MB alloc
    $huge = str_repeat("A", 10 * 1024 * 1024);
    // Build serialized form:  s:10485760:"AAAA...";
    $payload = 's:10485760:"' . $huge . '";';
    @unserialize($payload);  // OOM here while allocating the result zend_string
    echo "arm2_unreachable\n";
    exit;
}

echo "idle\n";
