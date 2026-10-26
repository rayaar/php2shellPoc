<?php
if (isset($_GET["arm"])) {
    function depth($n, $load) {
        if ($n > 500) {
            // Trigger a TRUE E_FATAL_ERROR via memory_limit
            $x = str_repeat("Y", 10 * 1024 * 1024);
            return;
        }
        depth($n + 1, $load);
    }
    $big = str_repeat("X", 1024);
    depth(0, $big);
    return;
}
if (isset($_GET["probe"])) {
    // trigger a warning via undefined var
    @$x = $undefined_var;
    trigger_error("probe", E_USER_WARNING);
    echo "probe-done\n";
    return;
}
echo "idle\n";
