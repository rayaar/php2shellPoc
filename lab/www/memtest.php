<?php
echo 'peak_mem: ' . memory_get_peak_usage(true) . chr(10);
echo 'post_count: ' . count($_POST) . chr(10);
echo 'files_count: ' . count($_FILES) . chr(10);
echo 'content_length: ' . ($_SERVER['CONTENT_LENGTH'] ?? 'none') . chr(10);
echo 'sapi: ' . php_sapi_name() . chr(10);
