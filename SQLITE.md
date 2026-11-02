# SQLite backend (v1.20.0)

`index.php` remains the only production application file. MySQL and MariaDB continue to use `mysqli`, including their existing administration tools. SQLite uses PHP's `PDO_SQLite` extension; **PDO MySQL is not used**. The SQLite adapter buffers query results, like the existing buffered MySQL path.

PDO_SQLite is intentional: on supported older PHP versions, the native `SQLite3` result API truncates TEXT containing embedded NUL characters. The SQLite adapter preserves those bytes as well as BLOB values.

## Enable SQLite

Requirements: PHP 7.4+, PDO_SQLite, and an existing initialized SQLite 3 database. On Debian/Ubuntu, `php-sqlite3` normally supplies PDO_SQLite too. The existing PHP extensions used by the application, including sessions, JSON and ctype, are still needed. The test fixture builder additionally uses SQLite3; production does not require it.

1. Put database files in a dedicated directory **outside the document root and application directory**. Give the PHP process read/write access to the files and directory (SQLite may need journal/WAL sidecars). Restrict access by other operating-system users. Back up databases before using any administration tool.
2. Configure the PHP process environment with `MS_SQLITE_ROOT` (an absolute private directory) and `MS_SQLITE_PASSWORD_HASH` (a `password_hash()` result). Both are required. Constants of the same names supplied by a trusted server bootstrap are also supported. No source edit is needed when using environment variables.
3. Select **SQLite** on the login form, enter an existing filename relative to the configured root (or its full path within that root), and enter the administrator password.

Example hash generation, reading the password from standard input rather than putting it into shell history:

```sh
php -r '$password = rtrim(fgets(STDIN), "\r\n"); echo password_hash($password, PASSWORD_DEFAULT), PHP_EOL;'
```

Example environment values (use the generated hash, with single quotes to preserve dollar signs):

```sh
export MS_SQLITE_ROOT='/srv/private/adminer-databases'
export MS_SQLITE_PASSWORD_HASH='<generated password hash>'
```

Set these on the actual Apache/PHP-FPM process using your hosting configuration. Shell exports alone do not change an already running web server's environment. SQLite has no native username/password system: this password protects access through this application. It does not encrypt the database file. The existing recommendation to restrict the application by HTTPS and web-server authentication or IP remains applicable.

No file is created by login. Missing files, uninitialized files, URI paths, memory databases, out-of-root symlinks and public database files are rejected. PDO opens existing files with READWRITE and without CREATE. Rotating the configured password hash invalidates existing SQLite sessions on their next connection. Every connection revalidates the canonical path against the configured root.

## Implemented

- Engine selection with legacy MySQL sessions defaulting to MySQL.
- Driver boundary for connections, result handling, quoting, prepared values and metadata. Existing `mysqli` SQL remains native; user SQL is not translated into another dialect.
- SQLite table/view discovery, declared types and storage affinities, defaults, generated columns, primary-key positions, indexes, foreign keys and trigger definitions. Structure pages use `sqlite_master` and PRAGMAs, not fabricated MySQL metadata.
- Existing table/card browsing, comparison/text/NULL filters, global search, aggregates, sorting, pagination and Show more.
- Inserts, updates, deletes, selected-row deletes, bulk updates and individual row cloning. Values use native bound parameters; BLOBs use explicit binary binding. Insert forms can omit a column with **Use default SQL**. Generated columns are excluded from writes.
- Full signed 64-bit INTEGER PRIMARY KEY values, composite keys and WITHOUT ROWID tables. Nullable SQLite primary keys fall back to an unshadowed implicit rowid, so duplicate or NULL keys cannot cause multi-row edits/deletes. Typed key identities preserve TEXT/BLOB distinctions and REAL precision, including on PHP 7.4. The internal identity is hidden from displayed columns; unchanged cells retain their SQLite storage classes.
- Read-only views. If all implicit rowid names are shadowed and no guaranteed non-NULL primary key exists, the table is browse-only; use SQL for deliberate changes.
- Native SQLite SQL execution, multiple statements, transaction commands, CTEs, trigger bodies, result limits, errors, query history and EXPLAIN. Parameters respect SQLite quoting and comment rules.
- Existing profiles, table/column presentation settings, saved searches, saved views and virtual foreign keys. MySQL profile/presence identifiers are unchanged. SQLite configuration is isolated by canonical database path.

Foreign-key enforcement is enabled on every SQLite connection; the busy timeout is five seconds. SQL expressions remain an explicit administrator option. SQLite's dynamic types are preserved: declared `TINYINT`/`VARCHAR(n)` do not acquire MySQL width or length restrictions. SQLite itself enforces STRICT tables and constraints supported by the installed SQLite library.

The SQL editor intentionally refuses ATTACH/DETACH, VACUUM INTO, extension/filesystem functions and PRAGMAs outside a small read-only allowlist. This boundary also covers prepared statements and EXPLAIN-prefixed PRAGMAs on PHP 7.4, where SQLite's authorizer API is unavailable. Only the selected file is accessible through the editor.

## Remaining parity work

This is the first usable SQLite backend, not full feature parity.

| Area | SQLite behavior in this release |
| --- | --- |
| Visual create/alter table and index/constraint editors | Hidden; use native SQLite DDL in SQL command. No automatic table-rebuild migration tool. |
| Import, database/query exports, XLSX and ZIP exports | Hidden/guarded; SQLite dump/restore and CSV import/export still need dedicated implementation. Row BLOB downloads and CREATE statement downloads work. |
| Visual query builder and schema diagram | Hidden; table filters/aggregates and SQL command remain available. |
| Dedicated view/trigger editors | Hidden; definitions are inspected in Structure and can be managed using SQL. |
| Column statistics/duplicate analysis, temporal shortcut filters, REGEXP and MySQL full-text filters | Hidden/guarded; normal comparisons and text search work. SQLite FTS and date semantics need dedicated UI support. |
| Soft delete, repair recipes and batch cloning | Disabled/hidden; ordinary delete removes the row. Single-row cloning works. |
| Browser diagnostics page | MySQL diagnostics remain unchanged. SQLite regressions run through the CLI/CI tests below; integration into the in-app diagnostics report is pending. |
| Server users/grants, processes, server variables, routines and scheduled events | MySQL-only, hidden and guarded. SQLite has no corresponding server facilities. |
| Multiple attached databases and database-file creation/deletion | Intentionally unavailable through this first backend. |

On PHP 7.4, empty SELECT column names are obtained without executing the query twice; empty DML RETURNING results may use generic column headers. Non-finite REAL primary keys and integer keys outside the PHP platform integer range require deliberate SQL operations.

Very large SQL results are buffered before the display cap is applied, matching the existing MySQL path; result streaming is future work. SQLite features such as generated columns, STRICT tables or RETURNING require a sufficiently recent system SQLite library even when PHP itself is supported.

## Validation

```sh
php -l index.php
php tests/database_backends.php sqlite
python3 tests/http_sqlite.py

# Dedicated disposable test server: requires CREATE/DROP DATABASE privileges.
MS_TEST_HOST=127.0.0.1 MS_TEST_PORT=3306 MS_TEST_USER=root \
  MS_TEST_PASSWORD='test-server-password' php tests/database_backends.php mysql
```

The MySQL runner creates and removes a randomly named `ms_backend_test_*` database and runs the existing embedded diagnostic suite, which creates its own randomly named disposable database. It never selects a user database. The SQLite runner uses a private temporary directory; the HTTP runner copies the single production file into a temporary web root and tests login, browsing, CRUD, SQL, CSRF and unsupported-route guards.

The GitHub Actions matrix runs PHP 7.4, 8.3, 8.4 and 8.5 against MySQL 8.0 and MariaDB 10.11, plus SQLite and the HTTP flow on every job. Runtime deprecations fail the CLI regression runs; the HTTP flow checks for PHP diagnostics with `E_ALL` enabled. See [PHP compatibility](PHP_COMPATIBILITY.md) for the v1.20.1 changes and additional checks.

### Locally verified runtime matrix (20 October 2026)

| PHP | SQLite 3.45.1 | MySQL 8.0.46 | MariaDB 10.11.14 |
| --- | --- | --- | --- |
| 7.4.3 | 67 backend checks + 37 HTTP checks passed | 10 runner checks, including all 42 embedded diagnostics, passed | 10 runner checks, including all 42 embedded diagnostics, passed |
| 8.3.6 | 67 backend checks + 37 HTTP checks passed | 10 runner checks, including all 42 embedded diagnostics, passed | 10 runner checks, including all 42 embedded diagnostics, passed |

The MySQL 8 run also identified six failures in the unchanged v1.19.2 embedded diagnostics. The baseline was reproduced separately. Quoting its reserved `empty` alias and comparing repair keys solely through their canonical binary representation resolves them on MySQL 8 while preserving the MariaDB results.
