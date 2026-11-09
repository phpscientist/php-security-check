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

$eq('fixed 7.4', fixedVersion('7.4.0', $range), '7.4.23');
$eq('fixed v-prefix', fixedVersion('v6.1.0', $range), '6.4.50');
$eq('fixed none', fixedVersion('8.2.0', $range), null);
$eq('fixed open range', fixedVersion('1.0.0', '>=1.0.0'), null);
$eq('patch', upgradeSize('v7.4.0', '7.4.23'), 'patch');
$eq('minor', upgradeSize('6.1.0', '6.4.50'), 'minor');
$eq('major', upgradeSize('5.4.0', '6.0.0'), 'major');

$ids = fn (string $p) => array_column(checkFrameworks(__DIR__ . "/fixtures/$p", true)['findings'], 'severity', 'id');
$l = $ids('laravel');
$eq('laravel debug', $l['laravel:app-debug'] ?? null, 'high');
$eq('laravel key', $l['laravel:app-key'] ?? null, 'critical');
$eq('laravel debugbar', $l['laravel:barryvdh/laravel-debugbar'] ?? null, 'medium');
$eq('public env', $l['env:public'] ?? null, 'critical');
$eq('debugbar in dev is fine', isset($ids('laravel-ok')['laravel:barryvdh/laravel-debugbar']), false);
$eq('symfony dev', $ids('symfony')['symfony:dev-mode'] ?? null, 'high');
$w = $ids('wordpress');
$eq('wp debug', $w['wordpress:debug'] ?? null, 'medium');
$eq('wp file edit', $w['wordpress:file-edit'] ?? null, 'low');

$report = ['findings' => [finding('a', 'php', 'high', 'A', 'x'), finding('b', 'php', 'high', 'B', 'x'), finding('c', 'php', 'high', 'C', 'x'), finding('d', 'php', 'high', 'D', 'x')], 'errors' => []];
$tmp = sys_get_temp_dir() . '/psc-' . bin2hex(random_bytes(4));
mkdir($tmp);
file_put_contents("$tmp/.php-security-check.json", json_encode(['ignore' => [
    ['id' => 'a', 'reason' => 'accepted', 'expires' => '2999-01-01'],
    ['id' => 'b', 'reason' => 'old', 'expires' => '2020-01-01'],
    ['id' => 'c', 'expires' => '2999-01-01'],
]]));
$out = applyIgnores($report, $tmp);
$eq('ignored only valid', array_column($out['findings'], 'id'), ['b', 'c', 'd']);
$eq('ignored count', count($out['ignored']), 1);
$eq('ignore problems reported', count($out['errors']), 2);
unlink("$tmp/.php-security-check.json");
rmdir($tmp);

$s = json_decode(sarif(['findings' => [finding('x:1', 'composer', 'critical', 'T', 'F', 'https://e.test')]]), true);
$eq('sarif version', $s['version'], '2.1.0');
$eq('sarif level', $s['runs'][0]['results'][0]['level'], 'error');
$eq('sarif uri', $s['runs'][0]['results'][0]['locations'][0]['physicalLocation']['artifactLocation']['uri'], 'composer.lock');

$src = preg_replace('/^    /m', '', probeSource('abc'));
$eq('probe has no env access', (bool) preg_match('/getenv|\$_ENV|\$_SERVER|phpinfo/', $src), false);
$eq('probe parses', (bool) @token_get_all($src), true);

echo $fails ? "$fails failed\n" : "All tests passed\n";
exit($fails ? 1 : 0);
