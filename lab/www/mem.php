<?php
echo "peak_mem: " . memory_get_peak_usage(true) . "\n";
echo "post_count: " . count($_POST) . "\n";
echo "files_count: " . count($_FILES) . "\n";
echo "content_length: " . ($_SERVER["CONTENT_LENGTH"] ?? "none") . "\n";
echo "request_method: " . $_SERVER["REQUEST_METHOD"] . "\n";
echo "sapi: " . php_sapi_name() . "\n";
