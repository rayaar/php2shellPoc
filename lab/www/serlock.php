<?php
error_reporting(E_ALL);
ini_set("display_errors", "1");

// Define both classes always — PHP has to accept both for the serialize/unserialize paths
class Bomb {
    public $data;
    public function __wakeup() {
        // Force OOM mid-wakeup
        $this->data = str_repeat("X", 10 * 1024 * 1024);
    }
}

class Watcher {
    public static $called = false;
    public function __wakeup() {
        self::$called = true;
    }
}

if (isset($_GET["arm"])) {
    // Request 1: unserialize a Bomb, OOM fires inside __wakeup
    $payload = 'O:4:"Bomb":1:{s:4:"data";s:0:"";}';
    @unserialize($payload);
    echo "arm_unreachable\n";
    exit;
}

if (isset($_GET["probe"])) {
    // Request 2: unserialize a Watcher, see if __wakeup fires
    $payload = 'O:7:"Watcher":0:{}';
    @unserialize($payload);
    echo Watcher::$called ? "wakeup_CALLED\n" : "wakeup_SKIPPED\n";
    exit;
}

if (isset($_GET["baseline"])) {
    // Baseline: same probe without any prior arm
    $payload = 'O:7:"Watcher":0:{}';
    @unserialize($payload);
    echo Watcher::$called ? "wakeup_CALLED\n" : "wakeup_SKIPPED\n";
    exit;
}

echo "idle\n";
