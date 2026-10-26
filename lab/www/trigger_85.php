<?php
// Request 1: trigger a fatal error with a deep stack to force OOM during backtrace capture
if (isset($_GET['arm'])) {
    // Build deep stack, fatal at the bottom
    function depth($n, $load) {
        if ($n > 1000) {
            // Force OOM on backtrace capture: args are 1KB each, 1000 frames = 1MB args alone
            // At 8M memory_limit, we're already consuming ~5-7M before this.
            // Trigger fatal via calling an undefined class method
            (new \stdClass)->nonExistentMethod($load);
        }
        depth($n + 1, $load);
    }
    $big = str_repeat("X", 1024);
    depth(0, $big);
    return;
}
// Request 2: trigger a simple warning
if (isset($_GET['probe'])) {
    $undef = $undefined_var; // Notice
    echo "probe ok\n";
    return;
}
echo "idle\n";
