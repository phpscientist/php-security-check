# php-security-check

One plain-English report on the security basics of a PHP project. It covers three things that are usually checked separately, or not at all:

- **PHP version:** end-of-life status, whether you're on the latest patch, and known critical PHP flaws
- **php.ini:** risky settings on a production server
- **Composer packages:** known vulnerabilities from the Packagist advisory database

No dependencies. It sends package names to Packagist, and nothing else about your project leaves your machine.

```text
[CRITICAL] PHP 8.5.3 is affected by PHP2Shell (CVE-2026-109618, CVE-2026-109619)
  Fix: Update to PHP 8.5.12 or later and restart every PHP worker.

[HIGH] display_errors should be Off
  Fix: Set display_errors = Off in the php.ini your web server loads.
```

## Run it

```bash
curl -LO https://raw.githubusercontent.com/phpscientist/php-security-check/main/bin/php-security-check
php php-security-check /path/to/project
```

## Check what your web server really runs

The command line and the web server often use different PHP versions and different settings. Check the ones that serve your site:

```bash
php php-security-check . --php-version=8.4.20 --ini=/etc/php/8.4/fpm/php.ini
```

To find them, upload this file briefly, open it once, then delete it:

```php
<?php echo PHP_VERSION, ' ', php_ini_loaded_file();
```

## GitHub Action

```yaml
- uses: actions/checkout@v4
- uses: phpscientist/php-security-check@v0
  with:
    php-version: '8.4.20'   # what production runs
    fail-on: high
```

The report appears in the job summary.

## Options

| Option | Meaning |
|---|---|
| `--php-version=X.Y.Z` | Check this version instead of the one running the tool |
| `--ini=FILE` | Check this php.ini instead of the current settings |
| `--format=json` | Machine-readable output |
| `--fail-on=LEVEL` | Exit 1 at `low`, `medium`, `high` or `critical`, or never with `none` (default `high`) |
| `--no-network` | Skip checks that need online data |

Exit codes: `0` nothing at the fail level, `1` findings at the fail level, `2` a check could not run.

A check that can't run is reported as **not checked**, never as passed.

## What it doesn't do

It doesn't scan your code or replace a security review. It checks common basics, and only the php.ini settings listed in the source.

## Data sources

[endoflife.date](https://endoflife.date), [Packagist security advisories](https://packagist.org/apidoc#list-security-advisories) and a small curated list of PHP core flaws in `data/php-core.json`.

Maintained by [Phpscientist](https://phpscientist.com/?utm_source=github&utm_medium=readme&utm_campaign=php-security-check).

MIT licensed.
