# php-security-check

**Is the PHP your web server actually runs safe?** One plain-English report, with the exact fix for each problem.

`composer audit` only looks at packages, and the `php -v` on your terminal is often not the PHP serving your site. This tool checks what's really running:

- **PHP version:** end-of-life status, latest patch and known critical PHP flaws
- **php.ini:** risky production settings, with a block ready to paste
- **Composer packages:** known vulnerabilities, with an upgrade plan
- **Laravel, Symfony and WordPress:** debug mode on, missing keys, dev tools in production, `.env` in the web root

No dependencies. It only sends package names to Packagist, and it never prints values from your `.env`.

```text
[CRITICAL] PHP 8.5.3 is affected by PHP2Shell (CVE-2026-109618, CVE-2026-109619)
  Fix: Update to PHP 8.5.12, then restart PHP-FPM or Apache. Debian/Ubuntu: apt install --only-upgrade 'php8.5-*'...

Upgrade plan
------------
symfony/yaml v7.4.0 -> 7.4.23 (patch, direct, fixes 5)
  composer update symfony/yaml --with-dependencies

Suggested php.ini settings
--------------------------
display_errors = Off
```

## Install

```bash
# Single file
curl -LO https://raw.githubusercontent.com/phpscientist/php-security-check/main/bin/php-security-check
php php-security-check /path/to/project

# PHAR, from the latest release
curl -LO https://github.com/phpscientist/php-security-check/releases/latest/download/php-security-check.phar
php php-security-check.phar /path/to/project

# Docker
docker build -t php-security-check https://github.com/phpscientist/php-security-check.git
docker run --rm -v "$PWD:/project" php-security-check .
```

Requires PHP 8.1 or later.

## Check what your web server really runs

The command line and the web server often use different PHP versions and settings. The probe reads the real ones:

```bash
php-security-check probe --dir=public
# upload the file if the project isn't on the server, then run the command it prints:
php-security-check . --probe='https://example.com/psc-probe-1a2b.php?token=...'
```

The probe file has a random name, needs a secret token, returns only the PHP version and the settings this tool checks, and deletes itself after one use or 15 minutes. Only use it on servers you're responsible for.

No probe? Pass the values yourself: `--php-version=8.4.20 --ini=/etc/php/8.4/fpm/php.ini`.

## GitHub Action

```yaml
- uses: actions/checkout@v4
- uses: phpscientist/php-security-check@v0
  with:
    php-version: '8.4.20'   # what production runs
    fail-on: high
    sarif: psc.sarif
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: psc.sarif
```

The report appears in the job summary, and SARIF results appear in the repository's Security tab.

## Accept a risk, with an expiry date

Every finding prints an `Id`. To accept one, add `.php-security-check.json` to the project:

```json
{
  "ignore": [
    { "id": "ini:expose_php", "reason": "Hidden by our proxy", "expires": "2027-03-31" }
  ]
}
```

A reason and an expiry date are required. When the date passes, the finding comes back.

## Options

| Option | Meaning |
|---|---|
| `--probe=URL` | Read PHP version and settings from a probe file (https only) |
| `--php-version=X.Y.Z` | Check this version instead of the one running the tool |
| `--ini=FILE` | Check this php.ini instead of the current settings |
| `--format=json` | Machine-readable output |
| `--sarif=FILE` | Also write a SARIF report |
| `--fail-on=LEVEL` | Exit 1 at `low`, `medium`, `high` or `critical`, or never with `none` (default `high`) |
| `--no-network` | Skip checks that need online data |

Exit codes: `0` nothing at the fail level, `1` findings at the fail level, `2` a check could not run.

A check that can't run is reported as **not checked**, never as passed.

## What it doesn't do

It doesn't scan your code or replace a security review. It doesn't tell you whether a vulnerable feature is reachable in your application. Laravel, Symfony and WordPress checks need the project's `.env` or `wp-config.php`, so run those on the server. The list of PHP core flaws is curated by hand and can lag; the latest-patch check still flags an outdated PHP.

## Data sources

[endoflife.date](https://endoflife.date), the WordPress.org version API, [Packagist security advisories](https://packagist.org/apidoc#list-security-advisories) and a small curated list of PHP core flaws in `data/php-core.json`.

Maintained by [Phpscientist](https://phpscientist.com/?utm_source=github&utm_medium=readme&utm_campaign=php-security-check).

MIT licensed.
