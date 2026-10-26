<?php
echo 'content_type: ' . ($_SERVER['CONTENT_TYPE'] ?? 'MISSING') . chr(10);
echo 'content_length: ' . ($_SERVER['CONTENT_LENGTH'] ?? 'MISSING') . chr(10);
echo 'post_count: ' . count($_POST) . chr(10);
echo 'raw_input_len: ' . strlen(file_get_contents('php://input')) . chr(10);
echo 'peak_mem: ' . memory_get_peak_usage(true) . chr(10);
