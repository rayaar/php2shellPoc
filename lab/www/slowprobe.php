<?php
sleep(1); // give GDB time to attach while we're inside this request
echo "about to unserialize\n";
flush();
sleep(1);
$result = unserialize('O:8:"stdClass":1:{s:3:"foo";i:42;}');
echo "done: ", var_export($result, true), "\n";
