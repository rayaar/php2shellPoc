<?php
session_start();
$_SESSION["z"] = "x";
sleep(30);
echo "ok";
