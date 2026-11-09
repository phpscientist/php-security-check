<?php

declare(strict_types=1);

// Run with: php tests/run.php
putenv('PSC_TESTING=1');
$argv = ['x'];
require __DIR__ . '/../bin/php-security-check';

$fails = 0;
$eq = function (string $name, mixed $got, mixed $want) use (&$fails): void {
    if ($got !== $want) {
        $fails++;
        echo "FAIL $name: got " . var_export($got, true) . "\n";
    }
};

$range = '>=5.0,<5.4.56|>=6,<6.4.50|>=7,<7.4.23|>=8,<8.1.11';
foreach ([['5.4.55', true], ['5.4.56', false], ['v6.4.49', true], ['6.4.50', false], ['7.4.0', true], ['7.4.23', false], ['8.1.10', true], ['8.1.11', false], ['8.2.0', false], ['4.4.0', false]] as [$v, $want]) {
    $eq("range $v", versionInRange($v, $range), $want);
}
$eq('exact', versionInRange('1.2.3', '=1.2.3'), true);
$eq('exact no', versionInRange('1.2.4', '=1.2.3'), false);
$eq('empty', versionInRange('1.2.3', ''), false);

$core = json_decode((string) file_get_contents(__DIR__ . '/../data/php-core.json'), true)['advisories'];
$names = fn (string $v) => array_column(checkPhpVersion($v, true, $core)['findings'], 'severity');
$eq('8.5.3 affected', $names('8.5.3'), ['critical']);
$eq('8.5.12 clean', $names('8.5.12'), []);
$eq('8.2.34 affected', $names('8.2.34'), ['critical']);
$eq('8.1 older affected', $names('8.1.30'), ['critical']);
$eq('8.6 not flagged', $names('8.6.0'), []);

$r = checkIni(__DIR__ . '/fixtures/bad.ini');
$sev = array_column($r['findings'], 'severity', 'title');
$eq('display_errors flagged', $sev['display_errors should be Off'] ?? null, 'high');
$eq('allow_url_include flagged', $sev['allow_url_include should be Off'] ?? null, 'critical');
$eq('good setting not flagged', isset($sev['expose_php should be Off']), false);

echo $fails ? "$fails failed\n" : "All tests passed\n";
exit($fails ? 1 : 0);
