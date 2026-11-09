<?php

declare(strict_types=1);

// Run with: php -d phar.readonly=0 scripts/build-phar.php
$root = dirname(__DIR__);
$out = "$root/build/php-security-check.phar";
@mkdir(dirname($out));
@unlink($out);
$phar = new Phar($out);
$phar->addFromString('bin/php-security-check', preg_replace('/^#!.*\n/', '', (string) file_get_contents("$root/bin/php-security-check")));
$phar->addFile("$root/data/php-core.json", 'data/php-core.json');
$phar->addFile("$root/LICENSE", 'LICENSE');
$phar->setStub("#!/usr/bin/env php\n<?php Phar::mapPhar('psc.phar'); require 'phar://psc.phar/bin/php-security-check'; __HALT_COMPILER();");
chmod($out, 0755);
echo "Built $out\n";
