<?php
error_reporting(E_ALL);
ini_set("fatal_error_backtraces", "1");

function deep($depth, $big) {
    if ($depth > 500) {
        // force OOM here
        $x = str_repeat("B", 10 * 1024 * 1024);  // 10MB alloc, triggers OOM at 8M limit
        return;
    }
    deep($depth + 1, $big);
}

$big = str_repeat("A", 1024);  // 1KB arg per frame
deep(0, $big);
