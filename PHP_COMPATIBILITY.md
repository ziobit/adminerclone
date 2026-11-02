# PHP compatibility (v1.20.1)

The single production file, `index.php`, supports PHP 7.4 through PHP 8.5. MySQL and MariaDB still use `mysqli`; SQLite still uses `PDO_SQLite`. No framework, Composer dependency or database migration is added.

## Changes for PHP 8.5

- The updater explicitly closes cURL resources on PHP 7.4 and releases `CurlHandle` objects on PHP 8+. This avoids the PHP 8.5 `curl_close()` deprecation.
- SQLite connections use `Pdo\Sqlite` driver constants when available, falling back to the older constants on PHP 7.4–8.3. Opening existing files in read/write mode without creating a new database is preserved.
- CSV delimiter detection, import parsing, rejected-row reports and the embedded export diagnostic specify the escape argument. Import parsing and rejected-row reports retain their existing backslash-escape behavior. Normal exports retain their existing empty escape, preserving literal backslashes.
- CI covers PHP 7.4, 8.3, 8.4 and 8.5 with both MySQL 8.0 and MariaDB 10.11. Every job also exercises SQLite, CSV handling, login/CRUD over HTTP, and both updater transports.

The changes follow the official [PHP 8.5 deprecations](https://www.php.net/manual/en/migration85.deprecated.php) and [PHP 8.4 CSV deprecations](https://www.php.net/manual/en/migration84.deprecated.php).

## Run the checks

Required test extensions: `mysqli`, `pdo_sqlite`, `sqlite3`, `curl`, `zip`, `ctype`, and sessions. The HTTP tests use Python 3's standard library and temporary local servers. They copy the application into a temporary directory; updater tests download only a local fixture and never install an update.

```sh
php -d error_reporting=-1 -l index.php
php tests/php_compatibility.php
php tests/database_backends.php sqlite
php tests/sqlite_tools.php
python3 tests/http_sqlite.py
python3 tests/http_updater.py

# Disposable test server only; requires CREATE/DROP DATABASE privileges.
MS_TEST_HOST=127.0.0.1 MS_TEST_PORT=3306 MS_TEST_USER=root \
  MS_TEST_PASSWORD='test-server-password' php tests/database_backends.php mysql
```

Set `PHP_BINARY` to a specific PHP executable when running the Python tests. PHP regression runners collect `E_DEPRECATED`/`E_USER_DEPRECATED` before loading the application and exit unsuccessfully if any are emitted, including errors suppressed with `@`. HTTP tests enable `E_ALL` and check responses and server logs.

### v1.21.0 SQLite compatibility

SQLite's new import/restore workflows use PDO-managed transactions: PHP 7.4 does not reliably report a transaction opened with raw SQL `BEGIN` through `PDO::inTransaction()`. If a trigger performs `RAISE(ROLLBACK)`, older PDO_SQLite versions (including PHP 7.4 and 8.3) can also retain a stale PDO transaction flag; after confirming that SQLite has already rolled back, the adapter reopens the same validated file without retrying any writes. These cases have dedicated regression coverage. MySQL/MariaDB transaction and CSV-escape behavior is unchanged. SQLite CSV imports use the same standard doubled-quote escaping as exports, preserving literal backslashes.

## Local validation, 26 October 2026

The following passed on **PHP 8.5.12** and **PHP 8.3.6**, using SQLite 3.45.1 and MariaDB 10.11.14:

- 10 compatibility/CSV checks.
- 67 SQLite backend checks.
- 38 SQLite HTTP checks.
- 2 updater download checks (cURL and streams).
- 11 MariaDB runner checks, including all 42 embedded diagnostics and rejected-import CSV validation.

The new regression checks also fail against the unchanged v1.20.0 source on PHP 8.5.12, reproducing the CSV, SQLite constant and updater deprecations.
