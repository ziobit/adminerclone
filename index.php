<?php
/**
 * MySQL Studio - single-file MySQL/MariaDB administration application.
 * PHP 7.4+, mysqli, no framework. Independent implementation based on the
 * public Adminer feature list; this file contains no Adminer source code.
 *
 * IMPORTANT: expose this file only through HTTPS and restrict it by IP or
 * web-server authentication. Delete it when it is no longer needed.
 */

declare(strict_types=1);

const MS_APP_NAME = 'MySQL Studio';
const MS_VERSION = '1.0.0';
const MS_ROWS_PER_PAGE = 50;
const MS_MAX_CELL_BYTES = 100000;

ini_set('session.use_strict_mode', '1');
ini_set('session.use_only_cookies', '1');
ini_set('session.cookie_httponly', '1');
if ((!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')) {
  ini_set('session.cookie_secure', '1');
}
session_name('mysql_studio_session');
session_start();

header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Referrer-Policy: no-referrer');
header("Content-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; font-src 'self' https://cdnjs.cloudflare.com; img-src 'self' data: blob:");

if (empty($_SESSION['ms_csrf'])) {
  $_SESSION['ms_csrf'] = bin2hex(random_bytes(32));
}

function h($value): string {
  return htmlspecialchars((string)$value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function qi(string $identifier): string {
  return '`' . str_replace('`', '``', $identifier) . '`';
}

function qs(mysqli $db, $value): string {
  if ($value === null) {
    return 'NULL';
  }
  return "'" . $db->real_escape_string((string)$value) . "'";
}

function g(string $key, string $default = ''): string {
  return isset($_GET[$key]) && !is_array($_GET[$key]) ? (string)$_GET[$key] : $default;
}

function p(string $key, string $default = ''): string {
  return isset($_POST[$key]) && !is_array($_POST[$key]) ? (string)$_POST[$key] : $default;
}

function csrf_field(): string {
  return '<input type="hidden" name="csrf" value="' . h($_SESSION['ms_csrf']) . '">';
}

function require_csrf(): void {
  $token = p('csrf');
  if ($token === '' || !hash_equals((string)$_SESSION['ms_csrf'], $token)) {
    http_response_code(403);
    throw new RuntimeException('The security token is invalid or expired. Reload the page and try again.');
  }
}

function url(array $changes = []): string {
  $query = $_GET;
  foreach ($changes as $key => $value) {
    if ($value === null || $value === '') {
      unset($query[$key]);
    } else {
      $query[$key] = $value;
    }
  }
  return '?' . http_build_query($query);
}

function go(array $changes = [], string $flash = '', string $type = 'success'): void {
  if ($flash !== '') {
    $_SESSION['ms_flash'] = [$type, $flash];
  }
  header('Location: ' . url($changes));
  exit;
}

function flash(): string {
  if (empty($_SESSION['ms_flash'])) {
    return '';
  }
  [$type, $message] = $_SESSION['ms_flash'];
  unset($_SESSION['ms_flash']);
  return '<div class="alert alert-' . h($type) . ' alert-dismissible fade show" role="alert">' . h($message) . '<button type="button" class="btn-close" data-bs-dismiss="alert"></button></div>';
}

function db_all(mysqli $db, string $sql): array {
  $result = $db->query($sql);
  if (!$result instanceof mysqli_result) {
    return [];
  }
  $rows = [];
  while ($row = $result->fetch_assoc()) {
    $rows[] = $row;
  }
  $result->free();
  return $rows;
}

function db_one(mysqli $db, string $sql): ?array {
  $rows = db_all($db, $sql);
  return $rows[0] ?? null;
}

function server_version(mysqli $db): string {
  $row = db_one($db, 'SELECT VERSION() AS version');
  return (string)($row['version'] ?? $db->server_info);
}

function is_mariadb(mysqli $db): bool {
  return stripos(server_version($db), 'mariadb') !== false;
}

function selected_db(): string {
  return isset($_SESSION['ms_db']) ? (string)$_SESSION['ms_db'] : '';
}

function connect_db(bool $selectDatabase = true): mysqli {
  if (empty($_SESSION['ms_login']) || !is_array($_SESSION['ms_login'])) {
    throw new RuntimeException('Not authenticated.');
  }
  $c = $_SESSION['ms_login'];
  mysqli_report(MYSQLI_REPORT_OFF);
  $socket = !empty($c['socket']) ? (string)$c['socket'] : null;
  $db = new mysqli((string)$c['host'], (string)$c['user'], (string)$c['password'], '', (int)$c['port'], $socket);
  if ($db->connect_errno) {
    throw new RuntimeException('Connection failed: ' . $db->connect_error);
  }
  $db->set_charset('utf8mb4');
  $database = selected_db();
  if ($selectDatabase && $database !== '' && !$db->select_db($database)) {
    unset($_SESSION['ms_db']);
    throw new RuntimeException('Cannot select database: ' . $db->error);
  }
  return $db;
}

function table_exists(mysqli $db, string $table): bool {
  $row = db_one($db, 'SELECT COUNT(*) AS n FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ' . qs($db, $table));
  return (int)($row['n'] ?? 0) > 0;
}

function table_columns(mysqli $db, string $table): array {
  return db_all($db, 'SELECT * FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ' . qs($db, $table) . ' ORDER BY ORDINAL_POSITION');
}

function primary_columns(mysqli $db, string $table): array {
  $rows = db_all($db, 'SELECT COLUMN_NAME FROM information_schema.KEY_COLUMN_USAGE WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ' . qs($db, $table) . " AND CONSTRAINT_NAME = 'PRIMARY' ORDER BY ORDINAL_POSITION");
  return array_column($rows, 'COLUMN_NAME');
}

function row_identity_where(mysqli $db, array $columns, array $source): string {
  $primary = primary_columns($db, g('table'));
  $names = $primary ?: array_column($columns, 'COLUMN_NAME');
  $parts = [];
  foreach ($names as $name) {
    $value = $source[$name] ?? null;
    $parts[] = qi((string)$name) . ($value === null ? ' IS NULL' : ' = ' . qs($db, $value));
  }
  return implode(' AND ', $parts) ?: '0=1';
}

function encode_identity(array $identity): string {
  return base64_encode(serialize($identity));
}

function decode_identity(string $encoded): ?array {
  $raw = base64_decode($encoded, true);
  if ($raw === false || $raw === '') {
    return null;
  }
  set_error_handler(static function (): bool { return true; });
  try {
    $value = unserialize($raw, ['allowed_classes' => false]);
  } finally {
    restore_error_handler();
  }
  return is_array($value) ? $value : null;
}

function sql_type_options(): array {
  return ['BIT', 'TINYINT', 'SMALLINT', 'MEDIUMINT', 'INT', 'INTEGER', 'BIGINT', 'DECIMAL', 'DEC', 'NUMERIC', 'FIXED', 'FLOAT', 'DOUBLE', 'DOUBLE PRECISION', 'REAL', 'BOOL', 'BOOLEAN', 'SERIAL', 'CHAR', 'VARCHAR', 'BINARY', 'VARBINARY', 'TINYTEXT', 'TEXT', 'MEDIUMTEXT', 'LONGTEXT', 'TINYBLOB', 'BLOB', 'MEDIUMBLOB', 'LONGBLOB', 'ENUM', 'SET', 'JSON', 'DATE', 'DATETIME', 'TIMESTAMP', 'TIME', 'YEAR', 'GEOMETRY', 'POINT', 'LINESTRING', 'POLYGON', 'MULTIPOINT', 'MULTILINESTRING', 'MULTIPOLYGON', 'GEOMETRYCOLLECTION', 'VECTOR', 'UUID', 'INET6'];
}

function build_column_sql(mysqli $db, array $source, bool $includeName = true): string {
  $name = trim((string)($source['name'] ?? ''));
  $type = strtoupper(trim((string)($source['type'] ?? 'VARCHAR')));
  if (!in_array($type, sql_type_options(), true)) {
    throw new RuntimeException('Unsupported column type.');
  }
  $length = trim((string)($source['length'] ?? ''));
  $sql = $includeName ? qi($name) . ' ' : '';
  $sql .= $type;
  if ($length !== '') {
    if (in_array($type, ['ENUM', 'SET'], true)) {
      $values = preg_split('/\r\n|\r|\n/', $length);
      $sql .= '(' . implode(', ', array_map(static function ($v) use ($db) { return qs($db, trim((string)$v)); }, array_filter($values, 'strlen'))) . ')';
    } elseif (preg_match('/^[0-9]+(?:\s*,\s*[0-9]+)?$/', $length)) {
      $sql .= '(' . $length . ')';
    }
  }
  if (!empty($source['unsigned']) && in_array($type, ['TINYINT', 'SMALLINT', 'MEDIUMINT', 'INT', 'INTEGER', 'BIGINT', 'DECIMAL', 'DEC', 'NUMERIC', 'FIXED', 'FLOAT', 'DOUBLE', 'DOUBLE PRECISION', 'REAL'], true)) {
    $sql .= ' UNSIGNED';
  }
  $charset = trim((string)($source['charset'] ?? ''));
  $collation = trim((string)($source['collation'] ?? ''));
  if ($charset !== '' && preg_match('/^[a-zA-Z0-9_]+$/', $charset)) {
    $sql .= ' CHARACTER SET ' . $charset;
  }
  if ($collation !== '' && preg_match('/^[a-zA-Z0-9_]+$/', $collation)) {
    $sql .= ' COLLATE ' . $collation;
  }
  $generated = trim((string)($source['generated'] ?? ''));
  if ($generated !== '') {
    $sql .= ' GENERATED ALWAYS AS (' . $generated . ') ' . (!empty($source['stored']) ? 'STORED' : 'VIRTUAL');
  } else {
    $sql .= !empty($source['nullable']) ? ' NULL' : ' NOT NULL';
    if (!empty($source['default_set'])) {
      $default = (string)($source['default'] ?? '');
      if (!empty($source['default_expression'])) {
        $sql .= ' DEFAULT ' . $default;
      } else {
        $sql .= ' DEFAULT ' . qs($db, $default);
      }
    }
    if (!empty($source['auto_increment'])) {
      $sql .= ' AUTO_INCREMENT';
    }
    if (!empty($source['on_update'])) {
      $sql .= ' ON UPDATE CURRENT_TIMESTAMP';
    }
  }
  $comment = trim((string)($source['comment'] ?? ''));
  if ($comment !== '') {
    $sql .= ' COMMENT ' . qs($db, $comment);
  }
  if (!empty($source['invisible'])) {
    $sql .= ' INVISIBLE';
  }
  return $sql;
}

function render_value($value, int $max = 500): string {
  if ($value === null) {
    return '<span class="badge text-bg-secondary">NULL</span>';
  }
  $string = (string)$value;
  if (preg_match('//u', $string) !== 1) {
    return '<span class="badge text-bg-warning">BINARY ' . strlen($string) . ' bytes</span>';
  }
  if (strlen($string) > $max) {
    $string = substr($string, 0, $max) . '…';
  }
  return '<span class="cell-value">' . nl2br(h($string)) . '</span>';
}

function split_sql_script(string $sql): array {
  $statements = [];
  $buffer = '';
  $delimiter = ';';
  $quote = '';
  $lineComment = false;
  $blockComment = false;
  $lines = preg_split('/(?<=\n)/', str_replace("\r\n", "\n", $sql));
  foreach ($lines as $line) {
    if ($quote === '' && !$blockComment && trim($buffer) === '' && preg_match('/^\s*DELIMITER\s+(\S+)\s*$/i', trim($line), $match)) {
      $delimiter = $match[1];
      $buffer = '';
      continue;
    }
    $length = strlen($line);
    for ($i = 0; $i < $length; $i++) {
      $char = $line[$i];
      $next = $i + 1 < $length ? $line[$i + 1] : '';
      if ($lineComment) {
        $buffer .= $char;
        if ($char === "\n") {
          $lineComment = false;
        }
        continue;
      }
      if ($blockComment) {
        $buffer .= $char;
        if ($char === '*' && $next === '/') {
          $buffer .= '/';
          $i++;
          $blockComment = false;
        }
        continue;
      }
      if ($quote !== '') {
        $buffer .= $char;
        if ($char === '\\' && $next !== '') {
          $buffer .= $next;
          $i++;
        } elseif ($char === $quote) {
          if ($next === $quote) {
            $buffer .= $next;
            $i++;
          } else {
            $quote = '';
          }
        }
        continue;
      }
      if ($char === '#' || ($char === '-' && $next === '-' && ($i + 2 >= $length || ctype_space($line[$i + 2])))) {
        $lineComment = true;
        $buffer .= $char;
        continue;
      }
      if ($char === '/' && $next === '*') {
        $blockComment = true;
        $buffer .= '/*';
        $i++;
        continue;
      }
      if (in_array($char, ["'", '"', '`'], true)) {
        $quote = $char;
        $buffer .= $char;
        continue;
      }
      if ($delimiter !== '' && substr($line, $i, strlen($delimiter)) === $delimiter) {
        if (trim($buffer) !== '') {
          $statements[] = trim($buffer);
        }
        $buffer = '';
        $i += strlen($delimiter) - 1;
        continue;
      }
      $buffer .= $char;
    }
  }
  if (trim($buffer) !== '') {
    $statements[] = trim($buffer);
  }
  return $statements;
}

function execute_sql(mysqli $db, string $sql): array {
  $started = microtime(true);
  $results = [];
  $statements = split_sql_script($sql);
  if (!$statements) {
    throw new RuntimeException('No executable SQL statement found.');
  }
  foreach ($statements as $statement) {
    $result = $db->query($statement);
    if ($result === false) {
      throw new RuntimeException($db->error . ' — Statement: ' . substr($statement, 0, 300));
    }
    do {
    if ($result instanceof mysqli_result) {
      $fields = $result->fetch_fields();
      $rows = [];
      while ($row = $result->fetch_assoc()) {
        $rows[] = $row;
        if (count($rows) >= 1000) {
          break;
        }
      }
      $results[] = ['fields' => $fields, 'rows' => $rows, 'count' => $result->num_rows, 'affected' => null, 'info' => ''];
      $result->free();
    } else {
      $results[] = ['fields' => [], 'rows' => [], 'count' => null, 'affected' => $db->affected_rows, 'info' => $db->info];
    }
      if (!$db->more_results()) {
        break;
      }
      if (!$db->next_result()) {
        if ($db->errno) {
          throw new RuntimeException($db->error);
        }
        break;
      }
      $result = $db->store_result();
    } while (true);
    while ($db->more_results()) {
      $db->next_result();
      $extra = $db->store_result();
      if ($extra instanceof mysqli_result) {
        $extra->free();
      }
    }
    if ($db->errno) {
      throw new RuntimeException($db->error);
    }
  }
  return [$results, microtime(true) - $started];
}

function download_headers(string $filename, string $contentType = 'application/octet-stream'): void {
  header('Content-Type: ' . $contentType);
  header('Content-Disposition: attachment; filename="' . str_replace(['"', "\r", "\n"], '', $filename) . '"');
  header('X-Content-Type-Options: nosniff');
}

function dump_database(mysqli $db, array $tables, bool $structure, bool $data, bool $drop): void {
  $database = selected_db();
  echo "-- MySQL Studio export\n-- Database: " . str_replace("\n", ' ', $database) . "\n-- Generated: " . gmdate('Y-m-d H:i:s') . " UTC\n\n";
  echo "SET NAMES utf8mb4;\nSET FOREIGN_KEY_CHECKS=0;\n\n";
  $views = [];
  foreach ($tables as $table) {
    $meta = db_one($db, 'SELECT TABLE_TYPE FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ' . qs($db, $table));
    if (($meta['TABLE_TYPE'] ?? '') === 'VIEW') {
      $views[] = $table;
      continue;
    }
    if ($structure) {
      $create = db_one($db, 'SHOW CREATE TABLE ' . qi($table));
      if ($drop) {
        echo 'DROP TABLE IF EXISTS ' . qi($table) . ";\n";
      }
      echo ($create['Create Table'] ?? '') . ";\n\n";
    }
    if ($data) {
      $result = $db->query('SELECT * FROM ' . qi($table), MYSQLI_USE_RESULT);
      if ($result instanceof mysqli_result) {
        $columns = [];
        foreach ($result->fetch_fields() as $field) {
          $columns[] = qi($field->name);
        }
        $batch = [];
        while ($row = $result->fetch_assoc()) {
          $values = [];
          foreach ($row as $value) {
            $values[] = $value === null ? 'NULL' : qs($db, $value);
          }
          $batch[] = '(' . implode(', ', $values) . ')';
          if (count($batch) >= 100) {
            echo 'INSERT INTO ' . qi($table) . ' (' . implode(', ', $columns) . ") VALUES\n" . implode(",\n", $batch) . ";\n";
            $batch = [];
          }
        }
        if ($batch) {
          echo 'INSERT INTO ' . qi($table) . ' (' . implode(', ', $columns) . ") VALUES\n" . implode(",\n", $batch) . ";\n";
        }
        $result->free();
        echo "\n";
      }
    }
  }
  if ($structure) {
    foreach ($views as $view) {
      $create = db_one($db, 'SHOW CREATE VIEW ' . qi($view));
      if ($drop) {
        echo 'DROP VIEW IF EXISTS ' . qi($view) . ";\n";
      }
      echo ($create['Create View'] ?? '') . ";\n\n";
    }
    foreach (['PROCEDURE', 'FUNCTION'] as $kind) {
      $routines = db_all($db, 'SELECT ROUTINE_NAME FROM information_schema.ROUTINES WHERE ROUTINE_SCHEMA = DATABASE() AND ROUTINE_TYPE = ' . qs($db, $kind));
      foreach ($routines as $routine) {
        $name = (string)$routine['ROUTINE_NAME'];
        $create = db_one($db, 'SHOW CREATE ' . $kind . ' ' . qi($name));
        $key = 'Create ' . ucfirst(strtolower($kind));
        if ($drop) {
          echo 'DROP ' . $kind . ' IF EXISTS ' . qi($name) . ";\n";
        }
        echo "DELIMITER ;;\n" . ($create[$key] ?? '') . ";;\nDELIMITER ;\n\n";
      }
    }
    $events = db_all($db, 'SELECT EVENT_NAME FROM information_schema.EVENTS WHERE EVENT_SCHEMA = DATABASE()');
    foreach ($events as $event) {
      $name = (string)$event['EVENT_NAME'];
      $create = db_one($db, 'SHOW CREATE EVENT ' . qi($name));
      if ($drop) {
        echo 'DROP EVENT IF EXISTS ' . qi($name) . ";\n";
      }
      echo "DELIMITER ;;\n" . ($create['Create Event'] ?? '') . ";;\nDELIMITER ;\n\n";
    }
    $triggers = db_all($db, 'SELECT TRIGGER_NAME FROM information_schema.TRIGGERS WHERE TRIGGER_SCHEMA = DATABASE()');
    foreach ($triggers as $trigger) {
      $name = (string)$trigger['TRIGGER_NAME'];
      $create = db_one($db, 'SHOW CREATE TRIGGER ' . qi($name));
      if ($drop) {
        echo 'DROP TRIGGER IF EXISTS ' . qi($name) . ";\n";
      }
      echo "DELIMITER ;;\n" . ($create['SQL Original Statement'] ?? '') . ";;\nDELIMITER ;\n\n";
    }
  }
  echo "SET FOREIGN_KEY_CHECKS=1;\n";
}

function csv_export(mysqli $db, string $table): void {
  $result = $db->query('SELECT * FROM ' . qi($table), MYSQLI_USE_RESULT);
  if (!$result instanceof mysqli_result) {
    throw new RuntimeException($db->error);
  }
  $out = fopen('php://output', 'wb');
  $headers = [];
  foreach ($result->fetch_fields() as $field) {
    $headers[] = $field->name;
  }
  fputcsv($out, $headers);
  while ($row = $result->fetch_assoc()) {
    fputcsv($out, $row);
  }
  $result->free();
  fclose($out);
}

function raw_definition(mysqli $db, string $kind, string $name): string {
  if ($kind === 'VIEW') {
    $row = db_one($db, 'SHOW CREATE VIEW ' . qi($name));
    return (string)($row['Create View'] ?? '');
  }
  if ($kind === 'TRIGGER') {
    $row = db_one($db, 'SHOW CREATE TRIGGER ' . qi($name));
    return (string)($row['SQL Original Statement'] ?? '');
  }
  if ($kind === 'EVENT') {
    $row = db_one($db, 'SHOW CREATE EVENT ' . qi($name));
    return (string)($row['Create Event'] ?? '');
  }
  if (in_array($kind, ['PROCEDURE', 'FUNCTION'], true)) {
    $row = db_one($db, 'SHOW CREATE ' . $kind . ' ' . qi($name));
    return (string)($row['Create ' . ucfirst(strtolower($kind))] ?? '');
  }
  return '';
}

$error = '';

$layoutStarted = false;
try {
  if (p('action') === 'login') {
    require_csrf();
    $attempts = (int)($_SESSION['ms_attempts'] ?? 0);
    $lastAttempt = (int)($_SESSION['ms_last_attempt'] ?? 0);
    if ($attempts >= 5 && time() - $lastAttempt < 60) {
      throw new RuntimeException('Too many connection attempts. Wait one minute.');
    }
    $host = trim(p('host', 'localhost'));
    $port = max(1, min(65535, (int)p('port', '3306')));
    $user = trim(p('user'));
    $password = p('password');
    $socket = trim(p('socket'));
    if ($host === '' || $user === '' || $password === '') {
      throw new RuntimeException('Host, user and a non-empty password are required.');
    }
    mysqli_report(MYSQLI_REPORT_OFF);
    $test = new mysqli($host, $user, $password, '', $port, $socket !== '' ? $socket : null);
    if ($test->connect_errno) {
      $_SESSION['ms_attempts'] = $attempts + 1;
      $_SESSION['ms_last_attempt'] = time();
      throw new RuntimeException('Connection failed: ' . $test->connect_error);
    }
    $test->close();
    session_regenerate_id(true);
    $_SESSION['ms_login'] = compact('host', 'port', 'user', 'password', 'socket');
    $_SESSION['ms_attempts'] = 0;
    $_SESSION['ms_csrf'] = bin2hex(random_bytes(32));
    go(['page' => 'databases'], 'Connected successfully.');
  }

  if (p('action') === 'logout') {
    require_csrf();
    $_SESSION = [];
    if (ini_get('session.use_cookies')) {
      $params = session_get_cookie_params();
      setcookie(session_name(), '', time() - 42000, $params['path'], $params['domain'], (bool)$params['secure'], (bool)$params['httponly']);
    }
    session_destroy();
    header('Location: ?');
    exit;
  }

  if (!empty($_SESSION['ms_login'])) {
    $db = connect_db(false);

    if (g('download') === 'blob') {
      $table = g('table');
      $column = g('column');
      if (!table_exists($db, $table)) {
        throw new RuntimeException('Table not found.');
      }
      $columns = table_columns($db, $table);
      $allowed = array_column($columns, 'COLUMN_NAME');
      if (!in_array($column, $allowed, true)) {
        throw new RuntimeException('Column not found.');
      }
      $identity = decode_identity(g('id'));
      if (!is_array($identity)) {
        throw new RuntimeException('Invalid row identity.');
      }
      $sql = 'SELECT ' . qi($column) . ' AS value FROM ' . qi($table) . ' WHERE ' . row_identity_where($db, $columns, $identity) . ' LIMIT 1';
      $row = db_one($db, $sql);
      download_headers($table . '-' . $column . '.bin');
      echo $row['value'] ?? '';
      exit;
    }

    if (g('download') === 'export') {
      $db->select_db(selected_db());
      $format = g('format', 'sql');
      $selected = isset($_GET['tables']) && is_array($_GET['tables']) ? array_map('strval', $_GET['tables']) : [];
      $available = array_column(db_all($db, 'SELECT TABLE_NAME FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE() ORDER BY TABLE_NAME'), 'TABLE_NAME');
      $tables = $selected ? array_values(array_intersect($available, $selected)) : $available;
      if ($format === 'csv') {
        if (count($tables) !== 1) {
          throw new RuntimeException('CSV export requires exactly one table.');
        }
        download_headers($tables[0] . '.csv', 'text/csv; charset=UTF-8');
        echo "\xEF\xBB\xBF";
        csv_export($db, $tables[0]);
      } else {
        download_headers((selected_db() ?: 'database') . '-' . gmdate('Ymd-His') . '.sql', 'application/sql; charset=UTF-8');
        dump_database($db, $tables, g('structure', '1') === '1', g('data', '1') === '1', g('drop', '1') === '1');
      }
      exit;
    }

    if ($_SERVER['REQUEST_METHOD'] === 'POST' && p('action') !== '') {
      require_csrf();
      $action = p('action');

      if ($action === 'select_db') {
        $database = p('database');
        $allowed = array_column(db_all($db, 'SHOW DATABASES'), 'Database');
        if (!in_array($database, $allowed, true)) {
          throw new RuntimeException('Database is not available.');
        }
        $_SESSION['ms_db'] = $database;
        go(['page' => 'database', 'table' => null], 'Database selected.');
      }

      if ($action === 'create_database') {
        $name = trim(p('name'));
        $collation = trim(p('collation', 'utf8mb4_unicode_ci'));
        if ($name === '' || !preg_match('/^[a-zA-Z0-9_$-]+$/', $collation)) {
          throw new RuntimeException('Invalid database name or collation.');
        }
        $sql = 'CREATE DATABASE ' . qi($name) . ' COLLATE ' . $collation;
        if (!$db->query($sql)) {
          throw new RuntimeException($db->error);
        }
        $_SESSION['ms_db'] = $name;
        go(['page' => 'database'], 'Database created.');
      }

      if ($action === 'drop_database') {
        $name = selected_db();
        if ($name === '' || p('confirm_name') !== $name) {
          throw new RuntimeException('Type the exact database name to confirm.');
        }
        if (!$db->query('DROP DATABASE ' . qi($name))) {
          throw new RuntimeException($db->error);
        }
        unset($_SESSION['ms_db']);
        go(['page' => 'databases', 'table' => null], 'Database dropped.');
      }

      if (selected_db() !== '' && !$db->select_db(selected_db())) {
        throw new RuntimeException($db->error);
      }

      if ($action === 'run_sql') {
        $sql = p('sql');
        if (!empty($_FILES['sql_file']['tmp_name'])) {
          if ((int)$_FILES['sql_file']['size'] > 50 * 1024 * 1024) {
            throw new RuntimeException('SQL file is larger than 50 MB.');
          }
          $uploaded = file_get_contents((string)$_FILES['sql_file']['tmp_name']);
          if ($uploaded === false) {
            throw new RuntimeException('Cannot read uploaded SQL file.');
          }
          $sql = $uploaded;
        }
        if (trim($sql) === '') {
          throw new RuntimeException('Enter SQL or choose a SQL file.');
        }
        [$sqlResults, $sqlTime] = execute_sql($db, $sql);
        $_SESSION['ms_last_sql'] = $sql;
      } elseif ($action === 'create_table') {
        $name = trim(p('name'));
        $columns = isset($_POST['columns']) && is_array($_POST['columns']) ? $_POST['columns'] : [];
        $definitions = [];
        foreach ($columns as $column) {
          if (is_array($column) && trim((string)($column['name'] ?? '')) !== '') {
            $definitions[] = build_column_sql($db, $column);
          }
        }
        if ($name === '' || !$definitions) {
          throw new RuntimeException('A table name and at least one column are required.');
        }
        $engine = preg_match('/^[A-Za-z0-9_]+$/', p('engine')) ? p('engine') : 'InnoDB';
        $collation = preg_match('/^[A-Za-z0-9_]+$/', p('collation')) ? p('collation') : 'utf8mb4_unicode_ci';
        $sql = 'CREATE TABLE ' . qi($name) . ' (' . implode(', ', $definitions) . ') ENGINE=' . $engine . ' COLLATE=' . $collation;
        if (p('comment') !== '') {
          $sql .= ' COMMENT=' . qs($db, p('comment'));
        }
        if (!$db->query($sql)) {
          throw new RuntimeException($db->error);
        }
        go(['page' => 'structure', 'table' => $name], 'Table created.');
      } elseif ($action === 'alter_table') {
        $table = g('table');
        $newName = trim(p('name'));
        $parts = [];
        if ($newName !== '' && $newName !== $table) {
          $parts[] = 'RENAME TO ' . qi($newName);
        }
        if (preg_match('/^[A-Za-z0-9_]+$/', p('engine'))) {
          $parts[] = 'ENGINE=' . p('engine');
        }
        if (preg_match('/^[A-Za-z0-9_]+$/', p('collation'))) {
          $parts[] = 'COLLATE=' . p('collation');
        }
        if (p('auto_increment') !== '' && ctype_digit(p('auto_increment'))) {
          $parts[] = 'AUTO_INCREMENT=' . p('auto_increment');
        }
        $parts[] = 'COMMENT=' . qs($db, p('comment'));
        if (!$db->query('ALTER TABLE ' . qi($table) . ' ' . implode(', ', $parts))) {
          throw new RuntimeException($db->error);
        }
        go(['table' => $newName ?: $table], 'Table updated.');
      } elseif ($action === 'add_column') {
        $table = g('table');
        $sql = 'ALTER TABLE ' . qi($table) . ' ADD COLUMN ' . build_column_sql($db, $_POST);
        $position = p('position');
        if ($position === 'FIRST') {
          $sql .= ' FIRST';
        } elseif ($position !== '') {
          $sql .= ' AFTER ' . qi($position);
        }
        if (!$db->query($sql)) {
          throw new RuntimeException($db->error);
        }
        go([], 'Column added.');
      } elseif ($action === 'alter_column') {
        $table = g('table');
        $old = p('old_name');
        $sql = 'ALTER TABLE ' . qi($table) . ' CHANGE COLUMN ' . qi($old) . ' ' . build_column_sql($db, $_POST);
        $position = p('position');
        if ($position === 'FIRST') {
          $sql .= ' FIRST';
        } elseif ($position !== '') {
          $sql .= ' AFTER ' . qi($position);
        }
        if (!$db->query($sql)) {
          throw new RuntimeException($db->error);
        }
        go([], 'Column updated.');
      } elseif ($action === 'drop_column') {
        $sql = 'ALTER TABLE ' . qi(g('table')) . ' DROP COLUMN ' . qi(p('column'));
        if (!$db->query($sql)) {
          throw new RuntimeException($db->error);
        }
        go([], 'Column dropped.');
      } elseif ($action === 'drop_table') {
        $table = g('table');
        if (p('confirm_name') !== $table || !$db->query('DROP TABLE ' . qi($table))) {
          throw new RuntimeException($db->error ?: 'Type the exact table name to confirm.');
        }
        go(['page' => 'database', 'table' => null], 'Table dropped.');
      } elseif ($action === 'truncate_table') {
        if (!$db->query('TRUNCATE TABLE ' . qi(g('table')))) {
          throw new RuntimeException($db->error);
        }
        go([], 'Table emptied.');
      } elseif ($action === 'save_row') {
        $table = g('table');
        $columns = table_columns($db, $table);
        $input = isset($_POST['value']) && is_array($_POST['value']) ? $_POST['value'] : [];
        $nulls = isset($_POST['is_null']) && is_array($_POST['is_null']) ? $_POST['is_null'] : [];
        $expressions = isset($_POST['expression']) && is_array($_POST['expression']) ? $_POST['expression'] : [];
        $keepBlobs = isset($_POST['keep_blob']) && is_array($_POST['keep_blob']) ? $_POST['keep_blob'] : [];
        $identity = decode_identity(p('identity'));
        $assignments = [];
        foreach ($columns as $column) {
          $name = (string)$column['COLUMN_NAME'];
          if (strpos((string)$column['EXTRA'], 'GENERATED') !== false) {
            continue;
          }
          $hasUpload = isset($_FILES['upload']['tmp_name'][$name]) && (string)$_FILES['upload']['tmp_name'][$name] !== '';
          if (is_array($identity) && isset($keepBlobs[$name]) && !$hasUpload) {
            continue;
          }
          if (!is_array($identity) && strpos((string)$column['EXTRA'], 'auto_increment') !== false && (string)($input[$name] ?? '') === '' && !isset($nulls[$name]) && empty($expressions[$name]) && !$hasUpload) {
            continue;
          }
          if (isset($nulls[$name])) {
            $sqlValue = 'NULL';
          } elseif ($hasUpload) {
            if ((int)$_FILES['upload']['size'][$name] > 25 * 1024 * 1024) {
              throw new RuntimeException('Uploaded BLOB is larger than 25 MB.');
            }
            $bytes = file_get_contents((string)$_FILES['upload']['tmp_name'][$name]);
            $sqlValue = qs($db, $bytes === false ? '' : $bytes);
          } elseif (!empty($expressions[$name])) {
            $sqlValue = (string)($input[$name] ?? 'NULL');
          } else {
            $sqlValue = qs($db, $input[$name] ?? '');
          }
          $assignments[$name] = $sqlValue;
        }
        if (is_array($identity)) {
          $set = [];
          foreach ($assignments as $name => $value) {
            $set[] = qi($name) . ' = ' . $value;
          }
          if (!$set) {
            go(['page' => 'select'], 'Nothing changed.', 'info');
          }
          $sql = 'UPDATE ' . qi($table) . ' SET ' . implode(', ', $set) . ' WHERE ' . row_identity_where($db, $columns, $identity) . ' LIMIT 1';
        } else {
          $sql = $assignments ? 'INSERT INTO ' . qi($table) . ' (' . implode(', ', array_map('qi', array_keys($assignments))) . ') VALUES (' . implode(', ', array_values($assignments)) . ')' : 'INSERT INTO ' . qi($table) . ' () VALUES ()';
        }
        if (!$db->query($sql)) {
          throw new RuntimeException($db->error);
        }
        go(['page' => 'select'], is_array($identity) ? 'Row updated.' : 'Row inserted.');
      } elseif ($action === 'clone_row') {
        $table = g('table');
        $columns = table_columns($db, $table);
        $identity = decode_identity(p('identity'));
        if (!is_array($identity)) {
          throw new RuntimeException('Invalid row identity.');
        }
        $row = db_one($db, 'SELECT * FROM ' . qi($table) . ' WHERE ' . row_identity_where($db, $columns, $identity) . ' LIMIT 1');
        if (!$row) {
          throw new RuntimeException('Row not found.');
        }
        $_SESSION['ms_clone'] = $row;
        go(['page' => 'row', 'mode' => 'insert', 'id' => null], 'Review the cloned values before saving.', 'info');
      } elseif ($action === 'delete_rows') {
        $table = g('table');
        $columns = table_columns($db, $table);
        $ids = isset($_POST['row_id']) && is_array($_POST['row_id']) ? $_POST['row_id'] : [];
        $conditions = [];
        foreach ($ids as $encoded) {
          $identity = decode_identity((string)$encoded);
          if (is_array($identity)) {
            $conditions[] = '(' . row_identity_where($db, $columns, $identity) . ')';
          }
        }
        if (!$conditions) {
          throw new RuntimeException('Select at least one row.');
        }
        if (!$db->query('DELETE FROM ' . qi($table) . ' WHERE ' . implode(' OR ', $conditions))) {
          throw new RuntimeException($db->error);
        }
        go([], $db->affected_rows . ' row(s) deleted.');
      } elseif ($action === 'bulk_update') {
        $table = g('table');
        $columns = array_column(table_columns($db, $table), 'COLUMN_NAME');
        $column = p('column');
        if (!in_array($column, $columns, true)) {
          throw new RuntimeException('Invalid column.');
        }
        $ids = isset($_POST['row_id']) && is_array($_POST['row_id']) ? $_POST['row_id'] : [];
        $meta = table_columns($db, $table);
        $conditions = [];
        foreach ($ids as $encoded) {
          $identity = decode_identity((string)$encoded);
          if (is_array($identity)) {
            $conditions[] = '(' . row_identity_where($db, $meta, $identity) . ')';
          }
        }
        if (!$conditions) {
          throw new RuntimeException('Select at least one row.');
        }
        $value = qs($db, p('bulk_value'));
        if (p('operation') === 'add') {
          $value = qi($column) . ' + ' . (float)p('bulk_value');
        } elseif (p('operation') === 'append') {
          $value = 'CONCAT(' . qi($column) . ', ' . qs($db, p('bulk_value')) . ')';
        } elseif (p('operation') === 'prepend') {
          $value = 'CONCAT(' . qs($db, p('bulk_value')) . ', ' . qi($column) . ')';
        } elseif (p('operation') === 'null') {
          $value = 'NULL';
        }
        if (!$db->query('UPDATE ' . qi($table) . ' SET ' . qi($column) . ' = ' . $value . ' WHERE ' . implode(' OR ', $conditions))) {
          throw new RuntimeException($db->error);
        }
        go([], $db->affected_rows . ' row(s) updated.');
      } elseif ($action === 'add_index') {
        $table = g('table');
        $type = strtoupper(p('index_type'));
        if (!in_array($type, ['INDEX', 'UNIQUE', 'FULLTEXT', 'SPATIAL', 'PRIMARY'], true)) {
          throw new RuntimeException('Invalid index type.');
        }
        $columns = isset($_POST['index_columns']) && is_array($_POST['index_columns']) ? array_map('strval', $_POST['index_columns']) : [];
        $allowed = array_column(table_columns($db, $table), 'COLUMN_NAME');
        $columns = array_values(array_intersect($allowed, $columns));
        if (!$columns) {
          throw new RuntimeException('Choose at least one column.');
        }
        $name = trim(p('index_name'));
        $sql = 'ALTER TABLE ' . qi($table) . ' ADD ' . ($type === 'PRIMARY' ? 'PRIMARY KEY' : $type . ' ' . qi($name ?: ('idx_' . implode('_', $columns)))) . ' (' . implode(', ', array_map('qi', $columns)) . ')';
        if (!$db->query($sql)) {
          throw new RuntimeException($db->error);
        }
        go([], 'Index created.');
      } elseif ($action === 'drop_index') {
        $name = p('index_name');
        $sql = 'ALTER TABLE ' . qi(g('table')) . ' DROP ' . ($name === 'PRIMARY' ? 'PRIMARY KEY' : 'INDEX ' . qi($name));
        if (!$db->query($sql)) {
          throw new RuntimeException($db->error);
        }
        go([], 'Index dropped.');
      } elseif ($action === 'rename_index') {
        $oldName = p('old_index_name');
        $newName = trim(p('new_index_name'));
        if ($oldName === 'PRIMARY' || $newName === '') {
          throw new RuntimeException('Primary keys cannot be renamed; a new index name is required.');
        }
        if (!$db->query('ALTER TABLE ' . qi(g('table')) . ' RENAME INDEX ' . qi($oldName) . ' TO ' . qi($newName))) {
          throw new RuntimeException($db->error);
        }
        go([], 'Index renamed.');
      } elseif ($action === 'add_foreign_key') {
        $table = g('table');
        $local = isset($_POST['local_columns']) && is_array($_POST['local_columns']) ? array_map('strval', $_POST['local_columns']) : [];
        $foreign = isset($_POST['foreign_columns']) && is_array($_POST['foreign_columns']) ? array_values(array_filter(array_map('strval', $_POST['foreign_columns']), 'strlen')) : [];
        if (!$local || count($local) !== count($foreign)) {
          throw new RuntimeException('Local and referenced column counts must match.');
        }
        $rule = static function (string $value): string {
          return in_array($value, ['RESTRICT', 'CASCADE', 'SET NULL', 'NO ACTION'], true) ? $value : 'RESTRICT';
        };
        $sql = 'ALTER TABLE ' . qi($table) . ' ADD CONSTRAINT ' . qi(p('constraint_name')) . ' FOREIGN KEY (' . implode(', ', array_map('qi', $local)) . ') REFERENCES ' . qi(p('reference_table')) . ' (' . implode(', ', array_map('qi', $foreign)) . ') ON UPDATE ' . $rule(p('on_update')) . ' ON DELETE ' . $rule(p('on_delete'));
        if (!$db->query($sql)) {
          throw new RuntimeException($db->error);
        }
        go([], 'Foreign key created.');
      } elseif ($action === 'drop_foreign_key') {
        if (!$db->query('ALTER TABLE ' . qi(g('table')) . ' DROP FOREIGN KEY ' . qi(p('constraint_name')))) {
          throw new RuntimeException($db->error);
        }
        go([], 'Foreign key dropped.');
      } elseif ($action === 'add_check') {
        $sql = 'ALTER TABLE ' . qi(g('table')) . ' ADD CONSTRAINT ' . qi(p('constraint_name')) . ' CHECK (' . p('expression') . ')';
        if (!$db->query($sql)) {
          throw new RuntimeException($db->error);
        }
        go([], 'Check constraint created.');
      } elseif ($action === 'drop_check') {
        $verb = is_mariadb($db) ? 'DROP CONSTRAINT ' : 'DROP CHECK ';
        if (!$db->query('ALTER TABLE ' . qi(g('table')) . ' ' . $verb . qi(p('constraint_name')))) {
          throw new RuntimeException($db->error);
        }
        go([], 'Check constraint dropped.');
      } elseif ($action === 'save_object') {
        $kind = strtoupper(p('kind'));
        $allowed = ['VIEW', 'TRIGGER', 'EVENT', 'PROCEDURE', 'FUNCTION'];
        if (!in_array($kind, $allowed, true)) {
          throw new RuntimeException('Invalid object type.');
        }
        $oldName = p('old_name');
        $definition = trim(p('definition'));
        if ($definition === '') {
          throw new RuntimeException('Definition is required.');
        }
        $originalDefinition = '';
        if ($oldName !== '') {
          $originalDefinition = raw_definition($db, $kind, $oldName);
          $db->query('DROP ' . $kind . ' IF EXISTS ' . qi($oldName));
        }
        if (!$db->query($definition)) {
          $createError = $db->error;
          if ($originalDefinition !== '') {
            $db->query($originalDefinition);
          }
          throw new RuntimeException($createError . ($originalDefinition !== '' ? ' The previous definition was restored.' : ''));
        }
        $targetPage = in_array($kind, ['PROCEDURE', 'FUNCTION'], true) ? 'routines' : strtolower($kind) . 's';
        go(['page' => $targetPage, 'name' => null], ucfirst(strtolower($kind)) . ' saved.');
      } elseif ($action === 'drop_object') {
        $kind = strtoupper(p('kind'));
        if (!in_array($kind, ['VIEW', 'TRIGGER', 'EVENT', 'PROCEDURE', 'FUNCTION'], true)) {
          throw new RuntimeException('Invalid object type.');
        }
        if (!$db->query('DROP ' . $kind . ' IF EXISTS ' . qi(p('name')))) {
          throw new RuntimeException($db->error);
        }
        go([], ucfirst(strtolower($kind)) . ' dropped.');
      } elseif ($action === 'call_routine') {
        $kind = strtoupper(p('kind'));
        $name = p('name');
        $args = isset($_POST['arg']) && is_array($_POST['arg']) ? $_POST['arg'] : [];
        $quoted = array_map(static function ($v) use ($db) { return qs($db, $v); }, $args);
        $statement = $kind === 'FUNCTION' ? 'SELECT ' . qi($name) . '(' . implode(', ', $quoted) . ') AS result' : 'CALL ' . qi($name) . '(' . implode(', ', $quoted) . ')';
        [$sqlResults, $sqlTime] = execute_sql($db, $statement);
      } elseif ($action === 'kill_process') {
        if (!$db->query('KILL ' . (int)p('process_id'))) {
          throw new RuntimeException($db->error);
        }
        go([], 'Process killed.');
      } elseif ($action === 'create_user') {
        $user = p('new_user');
        $host = p('new_host', '%');
        if ($user === '' || p('new_password') === '') {
          throw new RuntimeException('User and password are required.');
        }
        if (!$db->query('CREATE USER ' . qs($db, $user) . '@' . qs($db, $host) . ' IDENTIFIED BY ' . qs($db, p('new_password')))) {
          throw new RuntimeException($db->error);
        }
        go([], 'User created.');
      } elseif ($action === 'grant_privileges') {
        $privileges = isset($_POST['privilege']) && is_array($_POST['privilege']) ? array_map('strtoupper', array_map('strval', $_POST['privilege'])) : [];
        $allowed = ['ALL PRIVILEGES', 'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'CREATE', 'DROP', 'ALTER', 'INDEX', 'REFERENCES', 'EXECUTE', 'CREATE VIEW', 'SHOW VIEW', 'TRIGGER', 'EVENT', 'CREATE ROUTINE', 'ALTER ROUTINE'];
        $privileges = array_values(array_intersect($allowed, $privileges));
        if (!$privileges) {
          throw new RuntimeException('Choose at least one privilege.');
        }
        $scope = p('scope') === 'global' ? '*.*' : qi(p('grant_database')) . '.*';
        $mode = p('privilege_mode') === 'revoke' ? 'REVOKE' : 'GRANT';
        $sql = $mode . ' ' . implode(', ', $privileges) . ' ON ' . $scope . ($mode === 'GRANT' ? ' TO ' : ' FROM ') . qs($db, p('grant_user')) . '@' . qs($db, p('grant_host'));
        if ($mode === 'GRANT' && !empty($_POST['grant_option'])) {
          $sql .= ' WITH GRANT OPTION';
        }
        if (!$db->query($sql)) {
          throw new RuntimeException($db->error);
        }
        go([], 'Privileges updated.');
      } elseif ($action === 'alter_user') {
        $account = qs($db, p('alter_user')) . '@' . qs($db, p('alter_host'));
        $parts = [];
        if (p('alter_password') !== '') {
          $parts[] = 'IDENTIFIED BY ' . qs($db, p('alter_password'));
        }
        if (p('lock_mode') === 'lock') {
          $parts[] = 'ACCOUNT LOCK';
        } elseif (p('lock_mode') === 'unlock') {
          $parts[] = 'ACCOUNT UNLOCK';
        }
        if (!$parts) {
          throw new RuntimeException('Choose a password or account-lock change.');
        }
        if (!$db->query('ALTER USER ' . $account . ' ' . implode(' ', $parts))) {
          throw new RuntimeException($db->error);
        }
        go([], 'User updated.');
      } elseif ($action === 'drop_user') {
        if (!$db->query('DROP USER ' . qs($db, p('drop_user')) . '@' . qs($db, p('drop_host')))) {
          throw new RuntimeException($db->error);
        }
        go([], 'User dropped.');
      } elseif ($action === 'generic_sql') {
        $sql = p('statement');
        if (trim($sql) === '' || !$db->query($sql)) {
          throw new RuntimeException($db->error ?: 'Empty statement.');
        }
        go([], 'Operation completed.');
      }
    }
  }
} catch (Throwable $e) {
  $error = $e->getMessage();
}

function page_head(string $title, bool $authenticated): void {
  ?><!doctype html>
<html lang="en" data-bs-theme="auto">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title><?= h($title) ?> · <?= h(MS_APP_NAME) ?></title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.8/dist/css/bootstrap.min.css" rel="stylesheet">
  <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/7.0.1/css/all.min.css" rel="stylesheet">
  <style>
    :root{--sidebar:260px}body{min-height:100vh}.sidebar{width:var(--sidebar);position:fixed;inset:0 auto 0 0;overflow:auto;background:var(--bs-tertiary-bg);border-right:1px solid var(--bs-border-color)}.main{margin-left:var(--sidebar);padding:1.25rem}.brand{font-weight:700;letter-spacing:.02em}.table-scroll{overflow:auto;max-height:70vh}.table-scroll th{position:sticky;top:0;z-index:2;background:var(--bs-body-bg)}.cell-value{display:inline-block;max-width:420px;max-height:9rem;overflow:auto;white-space:pre-wrap}.sql-editor{font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace;min-height:220px;tab-size:2}.code{font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace;white-space:pre-wrap}.schema-canvas{position:relative;min-height:650px;background-image:radial-gradient(var(--bs-border-color) 1px,transparent 1px);background-size:20px 20px}.schema-table{position:relative;display:inline-block;vertical-align:top;width:240px;margin:12px}.schema-line{color:var(--bs-primary)}.nav-link.active{font-weight:600}.danger-zone{border:1px solid var(--bs-danger-border-subtle);background:var(--bs-danger-bg-subtle)}@media(max-width:991.98px){.sidebar{position:static;width:auto;height:auto}.main{margin-left:0}.sidebar .nav{flex-direction:row;overflow:auto;flex-wrap:nowrap}.sidebar .nav-link{white-space:nowrap}}@media print{.sidebar,.no-print{display:none!important}.main{margin:0;padding:0}.table-scroll{max-height:none;overflow:visible}}
  </style>
</head>
<body>
<?php if ($authenticated) { render_sidebar(); ?><main class="main"><?php } else { ?><main class="container py-5"><?php }
}

function page_foot(): void {
  ?></main>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.8/dist/js/bootstrap.bundle.min.js"></script>
<script>
(() => {
  'use strict';
  document.querySelectorAll('[data-confirm]').forEach(el => el.addEventListener('click', e => {
    if (!confirm(el.dataset.confirm || 'Are you sure?')) e.preventDefault();
  }));
  document.querySelectorAll('textarea.sql-editor').forEach(el => el.addEventListener('keydown', e => {
    if (e.key === 'Tab') { e.preventDefault(); const s=el.selectionStart, t=el.selectionEnd; el.value=el.value.substring(0,s)+'  '+el.value.substring(t); el.selectionStart=el.selectionEnd=s+2; }
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') el.form.requestSubmit();
  }));
  document.querySelectorAll('[data-check-all]').forEach(el => el.addEventListener('change', () => {
    document.querySelectorAll(el.dataset.checkAll).forEach(box => box.checked=el.checked);
  }));
  document.querySelectorAll('[data-theme]').forEach(el => el.addEventListener('click', () => {
    const theme=el.dataset.theme; document.documentElement.setAttribute('data-bs-theme',theme); localStorage.setItem('ms-theme',theme);
  }));
  const theme=localStorage.getItem('ms-theme'); if(theme) document.documentElement.setAttribute('data-bs-theme',theme);
})();
</script>
</body></html><?php
}

function render_sidebar(): void {
  $page = g('page', selected_db() ? 'database' : 'databases');
  $dbName = selected_db();
  $items = [
    ['databases', 'fa-database', 'Databases'],
    ['database', 'fa-table-list', 'Database'],
    ['sql', 'fa-terminal', 'SQL command'],
    ['export', 'fa-file-export', 'Export'],
    ['schema', 'fa-diagram-project', 'Schema'],
    ['views', 'fa-eye', 'Views'],
    ['routines', 'fa-code', 'Routines'],
    ['triggers', 'fa-bolt', 'Triggers'],
    ['events', 'fa-clock', 'Events'],
    ['processes', 'fa-list-check', 'Processes'],
    ['users', 'fa-users-gear', 'Users & rights'],
    ['variables', 'fa-sliders', 'Variables']
  ];
  ?><aside class="sidebar p-3">
    <div class="d-flex align-items-center justify-content-between mb-3">
      <a class="brand text-decoration-none" href="?page=databases"><i class="fa-solid fa-cube me-2"></i><?= h(MS_APP_NAME) ?></a>
      <div class="dropdown"><button class="btn btn-sm btn-secondary dropdown-toggle" data-bs-toggle="dropdown"><i class="fa-solid fa-circle-half-stroke"></i></button><ul class="dropdown-menu dropdown-menu-end"><li><button class="dropdown-item" data-theme="light">Light</button></li><li><button class="dropdown-item" data-theme="dark">Dark</button></li></ul></div>
    </div>
    <?php if ($dbName !== '') { ?><div class="small text-body-secondary mb-2 text-truncate" title="<?= h($dbName) ?>">Database: <strong><?= h($dbName) ?></strong></div><?php } ?>
    <nav class="nav nav-pills flex-column gap-1">
      <?php foreach ($items as [$key, $icon, $label]) { if ($dbName === '' && !in_array($key, ['databases', 'processes', 'users', 'variables'], true)) continue; ?>
        <a class="nav-link <?= $page === $key ? 'active' : 'text-body' ?>" href="?page=<?= h($key) ?>"><i class="fa-solid <?= h($icon) ?> fa-fw me-2"></i><?= h($label) ?></a>
      <?php } ?>
    </nav>
    <?php if ($dbName !== '') {
      try {
        $sideDb = connect_db();
        $tables = db_all($sideDb, "SELECT TABLE_NAME, TABLE_TYPE FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() ORDER BY TABLE_NAME");
        ?><hr><div class="small text-uppercase text-body-secondary mb-2">Objects</div><div class="list-group list-group-flush small">
        <?php foreach ($tables as $t) { $name=(string)$t['TABLE_NAME']; ?><a class="list-group-item list-group-item-action bg-transparent px-1 text-truncate" title="<?= h($name) ?>" href="?page=<?= $t['TABLE_TYPE']==='VIEW'?'select':'select' ?>&table=<?= urlencode($name) ?>"><i class="fa-solid <?= $t['TABLE_TYPE']==='VIEW'?'fa-eye':'fa-table' ?> fa-fw me-1"></i><?= h($name) ?></a><?php } ?>
        </div><?php
      } catch (Throwable $ignored) {}
    } ?>
    <hr><form method="post"><input type="hidden" name="action" value="logout"><?= csrf_field() ?><button class="btn btn-secondary btn-sm w-100"><i class="fa-solid fa-right-from-bracket me-1"></i>Log out</button></form>
    <div class="small text-body-secondary mt-3">v<?= h(MS_VERSION) ?> · PHP 7.4+</div>
  </aside><?php
}

function title_bar(string $title, string $subtitle = '', string $actions = ''): void {
  ?><div class="d-flex flex-wrap justify-content-between align-items-start gap-3 mb-4"><div><h1 class="h3 mb-1"><?= h($title) ?></h1><?php if ($subtitle !== '') { ?><div class="text-body-secondary"><?= h($subtitle) ?></div><?php } ?></div><div class="no-print"><?= $actions ?></div></div><?php
}

function render_sql_results(array $results, float $time): void {
  ?><div class="alert alert-success">Completed in <?= h(number_format($time, 4)) ?> seconds.</div><?php
  foreach ($results as $i => $result) {
    ?><section class="card mb-3"><div class="card-header">Result <?= $i + 1 ?></div><div class="card-body p-0"><?php
    if ($result['fields']) {
      ?><div class="table-responsive"><table class="table table-sm table-striped mb-0"><thead><tr><?php foreach ($result['fields'] as $field) { ?><th><?= h($field->name) ?></th><?php } ?></tr></thead><tbody><?php foreach ($result['rows'] as $row) { ?><tr><?php foreach ($row as $value) { ?><td><?= render_value($value) ?></td><?php } ?></tr><?php } ?></tbody></table></div><div class="p-2 small text-body-secondary"><?= h((string)$result['count']) ?> total row(s); display capped at 1,000.</div><?php
    } else {
      ?><div class="p-3"><?= h((string)$result['affected']) ?> row(s) affected. <?= h((string)$result['info']) ?></div><?php
    }
    ?></div></section><?php
  }
}

function column_form_fields(mysqli $db, array $values = [], string $prefix = ''): void {
  $name = (string)($values['name'] ?? '');
  $type = strtoupper((string)($values['type'] ?? 'VARCHAR'));
  $field = static function (string $key) use ($prefix): string {
    return $prefix === '' ? $key : $prefix . $key . ']';
  };
  ?><div class="row g-2">
    <div class="col-md-2"><label class="form-label">Name</label><input class="form-control" name="<?= h($field('name')) ?>" value="<?= h($name) ?>"></div>
    <div class="col-md-2"><label class="form-label">Type</label><select class="form-select" name="<?= h($field('type')) ?>"><?php foreach (sql_type_options() as $option) { ?><option<?= $option===$type?' selected':'' ?>><?= h($option) ?></option><?php } ?></select></div>
    <div class="col-md-2"><label class="form-label">Length / ENUM lines</label><input class="form-control" name="<?= h($field('length')) ?>" value="<?= h($values['length'] ?? '') ?>"></div>
    <div class="col-md-2"><label class="form-label">Default</label><input class="form-control" name="<?= h($field('default')) ?>" value="<?= h($values['default'] ?? '') ?>"></div>
    <div class="col-md-2"><label class="form-label">Collation</label><input class="form-control" name="<?= h($field('collation')) ?>" value="<?= h($values['collation'] ?? '') ?>"></div>
    <div class="col-md-2"><label class="form-label">Comment</label><input class="form-control" name="<?= h($field('comment')) ?>" value="<?= h($values['comment'] ?? '') ?>"></div>
    <div class="col-12 d-flex flex-wrap gap-3 small">
      <?php foreach ([['nullable','Nullable'],['default_set','Use default'],['default_expression','Default is expression'],['unsigned','Unsigned'],['auto_increment','Auto increment'],['on_update','ON UPDATE timestamp'],['invisible','Invisible'],['stored','Generated stored']] as [$key,$label]) { ?><label><input class="form-check-input" type="checkbox" name="<?= h($field($key)) ?>" value="1"<?= !empty($values[$key])?' checked':'' ?>> <?= h($label) ?></label><?php } ?>
    </div>
    <div class="col-md-8"><label class="form-label">Generated expression (leave empty for a normal column)</label><input class="form-control code" name="<?= h($field('generated')) ?>" value="<?= h($values['generated'] ?? '') ?>"></div>
  </div><?php
}

function page_login(string $error): void {
  page_head('Connect', false);
  ?><div class="row justify-content-center"><div class="col-lg-5 col-md-7"><div class="text-center mb-4"><div class="display-5"><i class="fa-solid fa-cube text-primary"></i></div><h1 class="h2"><?= h(MS_APP_NAME) ?></h1><p class="text-body-secondary">Single-file MySQL/MariaDB administration</p></div>
  <?php if ($error !== '') { ?><div class="alert alert-danger"><?= h($error) ?></div><?php } ?>
  <div class="card shadow-sm"><div class="card-body p-4"><form method="post" autocomplete="off"><input type="hidden" name="action" value="login"><?= csrf_field() ?>
    <div class="row g-3"><div class="col-8"><label class="form-label">Server</label><input class="form-control" name="host" value="<?= h(p('host','localhost')) ?>" required autofocus></div><div class="col-4"><label class="form-label">Port</label><input class="form-control" type="number" name="port" value="<?= h(p('port','3306')) ?>" min="1" max="65535" required></div>
    <div class="col-12"><label class="form-label">Unix socket <span class="text-body-secondary">(optional)</span></label><input class="form-control" name="socket" value="<?= h(p('socket')) ?>"></div>
    <div class="col-12"><label class="form-label">Username</label><input class="form-control" name="user" value="<?= h(p('user')) ?>" required></div>
    <div class="col-12"><label class="form-label">Password</label><input class="form-control" type="password" name="password" required></div>
    <div class="col-12"><button class="btn btn-primary w-100"><i class="fa-solid fa-plug me-2"></i>Connect</button></div></div>
  </form></div></div><div class="alert alert-warning small mt-3"><i class="fa-solid fa-shield-halved me-1"></i>Use HTTPS and restrict this file by IP or web-server authentication. Empty database passwords are intentionally refused.</div></div></div><?php
  page_foot();
}

function page_databases(mysqli $db): void {
  $rows = db_all($db, "SELECT SCHEMA_NAME, DEFAULT_CHARACTER_SET_NAME, DEFAULT_COLLATION_NAME FROM information_schema.SCHEMATA ORDER BY SCHEMA_NAME");
  title_bar('Databases', server_version($db), '<button class="btn btn-primary" data-bs-toggle="modal" data-bs-target="#createDatabase"><i class="fa-solid fa-plus me-1"></i>Create database</button>');
  ?><div class="card"><div class="table-responsive"><table class="table table-hover align-middle mb-0"><thead><tr><th>Name</th><th>Character set</th><th>Collation</th><th></th></tr></thead><tbody><?php foreach ($rows as $row) { ?><tr><td><i class="fa-solid fa-database text-primary me-2"></i><?= h($row['SCHEMA_NAME']) ?></td><td><?= h($row['DEFAULT_CHARACTER_SET_NAME']) ?></td><td><?= h($row['DEFAULT_COLLATION_NAME']) ?></td><td class="text-end"><form method="post"><input type="hidden" name="action" value="select_db"><input type="hidden" name="database" value="<?= h($row['SCHEMA_NAME']) ?>"><?= csrf_field() ?><button class="btn btn-primary btn-sm">Open</button></form></td></tr><?php } ?></tbody></table></div></div>
  <div class="modal fade" id="createDatabase" tabindex="-1"><div class="modal-dialog"><div class="modal-content"><form method="post"><div class="modal-header"><h2 class="modal-title fs-5">Create database</h2><button type="button" class="btn-close" data-bs-dismiss="modal"></button></div><div class="modal-body"><input type="hidden" name="action" value="create_database"><?= csrf_field() ?><label class="form-label">Name</label><input class="form-control mb-3" name="name" required><label class="form-label">Collation</label><input class="form-control" name="collation" value="utf8mb4_unicode_ci" required></div><div class="modal-footer"><button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button><button class="btn btn-primary">Create</button></div></form></div></div></div><?php
}

function page_database(mysqli $db): void {
  $rows = db_all($db, "SELECT TABLE_NAME,TABLE_TYPE,ENGINE,TABLE_ROWS,DATA_LENGTH,INDEX_LENGTH,TABLE_COLLATION,TABLE_COMMENT FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() ORDER BY TABLE_TYPE,TABLE_NAME");
  $size = 0; foreach ($rows as $row) $size += (int)$row['DATA_LENGTH'] + (int)$row['INDEX_LENGTH'];
  title_bar(selected_db(), count($rows) . ' object(s), ' . number_format($size / 1048576, 2) . ' MB', '<a class="btn btn-primary" href="?page=create_table"><i class="fa-solid fa-plus me-1"></i>Create table</a>');
  ?><div class="card mb-4"><div class="table-responsive"><table class="table table-hover align-middle mb-0"><thead><tr><th>Name</th><th>Type</th><th>Engine</th><th class="text-end">Rows</th><th class="text-end">Size</th><th>Collation</th><th>Comment</th><th></th></tr></thead><tbody><?php foreach ($rows as $row) { $table=(string)$row['TABLE_NAME']; ?><tr><td><a href="?page=select&amp;table=<?= urlencode($table) ?>"><?= h($table) ?></a></td><td><?= h($row['TABLE_TYPE']) ?></td><td><?= h($row['ENGINE']) ?></td><td class="text-end"><?= h(number_format((int)$row['TABLE_ROWS'])) ?></td><td class="text-end"><?= h(number_format(((int)$row['DATA_LENGTH']+(int)$row['INDEX_LENGTH'])/1024,1)) ?> KB</td><td><?= h($row['TABLE_COLLATION']) ?></td><td><?= h($row['TABLE_COMMENT']) ?></td><td class="text-end"><?php if ($row['TABLE_TYPE']==='BASE TABLE') { ?><a class="btn btn-secondary btn-sm" href="?page=structure&amp;table=<?= urlencode($table) ?>">Structure</a><?php } ?></td></tr><?php } ?></tbody></table></div></div>
  <div class="card danger-zone"><div class="card-body"><h2 class="h5 text-danger">Drop database</h2><p>This permanently removes every object and row in <strong><?= h(selected_db()) ?></strong>.</p><form method="post" class="row g-2 align-items-end"><input type="hidden" name="action" value="drop_database"><?= csrf_field() ?><div class="col-md-6"><label class="form-label">Type the database name to confirm</label><input class="form-control" name="confirm_name" required></div><div class="col-auto"><button class="btn btn-danger" data-confirm="Permanently drop this database?">Drop database</button></div></form></div></div><?php
}

function page_create_table(mysqli $db): void {
  title_bar('Create table', selected_db());
  ?><form method="post"><input type="hidden" name="action" value="create_table"><?= csrf_field() ?><div class="card mb-3"><div class="card-body"><div class="row g-3"><div class="col-md-4"><label class="form-label">Table name</label><input class="form-control" name="name" required></div><div class="col-md-3"><label class="form-label">Engine</label><input class="form-control" name="engine" value="InnoDB"></div><div class="col-md-3"><label class="form-label">Collation</label><input class="form-control" name="collation" value="utf8mb4_unicode_ci"></div><div class="col-md-2"><label class="form-label">Comment</label><input class="form-control" name="comment"></div></div></div></div>
  <?php for ($i=0;$i<6;$i++) { ?><div class="card mb-2"><div class="card-body"><?php column_form_fields($db, ['type'=>$i===0?'INT':'VARCHAR','length'=>$i===0?'11':'255','nullable'=>$i!==0,'auto_increment'=>$i===0], 'columns['.$i.']['); ?></div></div><?php } ?>
  <button class="btn btn-primary mt-2">Create table</button></form><?php
}

function parse_column_meta(array $column): array {
  $type = strtoupper((string)$column['DATA_TYPE']);
  $length = '';
  if (in_array($type,['CHAR','VARCHAR','BINARY','VARBINARY'],true)) $length=(string)$column['CHARACTER_MAXIMUM_LENGTH'];
  elseif (in_array($type,['DECIMAL','NUMERIC'],true)) $length=$column['NUMERIC_PRECISION'].','.$column['NUMERIC_SCALE'];
  elseif (in_array($type,['ENUM','SET'],true) && preg_match('/^[^(]+\((.*)\)$/s',(string)$column['COLUMN_TYPE'],$m)) $length=str_replace(["','","'"],["\n",''],$m[1]);
  return ['name'=>$column['COLUMN_NAME'],'type'=>$type,'length'=>$length,'nullable'=>$column['IS_NULLABLE']==='YES','default_set'=>$column['COLUMN_DEFAULT']!==null,'default'=>$column['COLUMN_DEFAULT']??'','default_expression'=>preg_match('/CURRENT_TIMESTAMP|^\(.+\)$/i',(string)($column['COLUMN_DEFAULT']??''))===1,'unsigned'=>strpos((string)$column['COLUMN_TYPE'],'unsigned')!==false,'auto_increment'=>strpos((string)$column['EXTRA'],'auto_increment')!==false,'on_update'=>stripos((string)$column['EXTRA'],'on update')!==false,'invisible'=>stripos((string)$column['EXTRA'],'invisible')!==false,'collation'=>$column['COLLATION_NAME']??'','comment'=>$column['COLUMN_COMMENT'],'generated'=>$column['GENERATION_EXPRESSION']??'','stored'=>strpos((string)$column['EXTRA'],'STORED')!==false];
}

function page_structure(mysqli $db): void {
  $table=g('table'); if(!table_exists($db,$table)) throw new RuntimeException('Table not found.');
  $columns=table_columns($db,$table); $status=db_one($db,'SHOW TABLE STATUS LIKE '.qs($db,$table));
  $indexes=db_all($db,'SHOW INDEX FROM '.qi($table));
  $foreign=db_all($db,"SELECT CONSTRAINT_NAME,COLUMN_NAME,REFERENCED_TABLE_NAME,REFERENCED_COLUMN_NAME,ORDINAL_POSITION FROM information_schema.KEY_COLUMN_USAGE WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=".qs($db,$table)." AND REFERENCED_TABLE_NAME IS NOT NULL ORDER BY CONSTRAINT_NAME,ORDINAL_POSITION");
  $checks=db_all($db,"SELECT tc.CONSTRAINT_NAME,cc.CHECK_CLAUSE FROM information_schema.TABLE_CONSTRAINTS tc JOIN information_schema.CHECK_CONSTRAINTS cc ON cc.CONSTRAINT_SCHEMA=tc.CONSTRAINT_SCHEMA AND cc.CONSTRAINT_NAME=tc.CONSTRAINT_NAME WHERE tc.TABLE_SCHEMA=DATABASE() AND tc.TABLE_NAME=".qs($db,$table)." AND tc.CONSTRAINT_TYPE='CHECK'");
  $triggers=db_all($db,'SELECT TRIGGER_NAME,ACTION_TIMING,EVENT_MANIPULATION,ACTION_STATEMENT FROM information_schema.TRIGGERS WHERE TRIGGER_SCHEMA=DATABASE() AND EVENT_OBJECT_TABLE='.qs($db,$table));
  title_bar('Structure: '.$table, $status['Comment']??'', '<a class="btn btn-primary" href="?page=select&amp;table='.urlencode($table).'">Browse data</a>');
  ?><ul class="nav nav-tabs mb-3"><li class="nav-item"><button class="nav-link active" data-bs-toggle="tab" data-bs-target="#columns">Columns</button></li><li class="nav-item"><button class="nav-link" data-bs-toggle="tab" data-bs-target="#indexes">Indexes</button></li><li class="nav-item"><button class="nav-link" data-bs-toggle="tab" data-bs-target="#foreign">Foreign keys</button></li><li class="nav-item"><button class="nav-link" data-bs-toggle="tab" data-bs-target="#checks">Checks</button></li><li class="nav-item"><button class="nav-link" data-bs-toggle="tab" data-bs-target="#table-triggers">Triggers</button></li><li class="nav-item"><button class="nav-link" data-bs-toggle="tab" data-bs-target="#partitions">Partitions</button></li><li class="nav-item"><button class="nav-link" data-bs-toggle="tab" data-bs-target="#table-settings">Table</button></li></ul>
  <div class="tab-content"><div class="tab-pane fade show active" id="columns"><div class="accordion" id="columnAccordion"><?php foreach($columns as $i=>$column){$meta=parse_column_meta($column);?><div class="accordion-item"><h2 class="accordion-header"><button class="accordion-button collapsed" data-bs-toggle="collapse" data-bs-target="#col<?= $i ?>"><span class="code"><?= h($column['COLUMN_NAME'].' '.$column['COLUMN_TYPE']) ?></span><?php if($column['COLUMN_KEY']){?><span class="badge text-bg-primary ms-2"><?= h($column['COLUMN_KEY']) ?></span><?php }?></button></h2><div id="col<?= $i ?>" class="accordion-collapse collapse" data-bs-parent="#columnAccordion"><div class="accordion-body"><form method="post"><input type="hidden" name="action" value="alter_column"><input type="hidden" name="old_name" value="<?= h($column['COLUMN_NAME']) ?>"><?= csrf_field() ?><?php column_form_fields($db,$meta); ?><div class="row mt-2"><div class="col-md-3"><label class="form-label">Position</label><select class="form-select" name="position"><option value="">Keep</option><option value="FIRST">First</option><?php foreach($columns as $c){if($c['COLUMN_NAME']!==$column['COLUMN_NAME']){?><option value="<?= h($c['COLUMN_NAME']) ?>">After <?= h($c['COLUMN_NAME']) ?></option><?php }}?></select></div><div class="col-md-9 d-flex align-items-end gap-2"><button class="btn btn-primary">Save column</button></form><form method="post"><input type="hidden" name="action" value="drop_column"><input type="hidden" name="column" value="<?= h($column['COLUMN_NAME']) ?>"><?= csrf_field() ?><button class="btn btn-danger" data-confirm="Drop this column and its data?">Drop</button></form></div></div></div></div></div><?php }?></div>
  <div class="card mt-3"><div class="card-header">Add column</div><div class="card-body"><form method="post"><input type="hidden" name="action" value="add_column"><?= csrf_field() ?><?php column_form_fields($db,['type'=>'VARCHAR','length'=>'255','nullable'=>true]); ?><div class="row mt-2"><div class="col-md-3"><select class="form-select" name="position"><option value="">At end</option><option value="FIRST">First</option><?php foreach($columns as $c){?><option value="<?= h($c['COLUMN_NAME']) ?>">After <?= h($c['COLUMN_NAME']) ?></option><?php }?></select></div><div class="col"><button class="btn btn-primary">Add column</button></div></div></form></div></div></div>
  <div class="tab-pane fade" id="indexes"><?php render_indexes($db,$table,$indexes,$columns); ?></div>
  <div class="tab-pane fade" id="foreign"><?php render_foreign_keys($db,$table,$foreign,$columns); ?></div>
  <div class="tab-pane fade" id="checks"><?php render_checks($db,$checks); ?></div>
  <div class="tab-pane fade" id="table-triggers"><?php render_table_triggers($triggers); ?></div>
  <div class="tab-pane fade" id="partitions"><?php render_partitions($db,$table); ?></div>
  <div class="tab-pane fade" id="table-settings"><?php render_table_settings($db,$table,$status); ?></div></div><?php
}

function render_table_triggers(array $triggers): void {
  ?><div class="card"><div class="table-responsive"><table class="table mb-0"><thead><tr><th>Name</th><th>Timing</th><th>Event</th><th>Statement</th><th></th></tr></thead><tbody><?php foreach($triggers as $trigger){?><tr><td><?= h($trigger['TRIGGER_NAME']) ?></td><td><?= h($trigger['ACTION_TIMING']) ?></td><td><?= h($trigger['EVENT_MANIPULATION']) ?></td><td class="code small"><?= h($trigger['ACTION_STATEMENT']) ?></td><td><a class="btn btn-secondary btn-sm" href="?page=triggers&amp;name=<?= urlencode((string)$trigger['TRIGGER_NAME']) ?>">Edit</a></td></tr><?php }?></tbody></table></div><div class="card-footer"><a class="btn btn-primary" href="?page=triggers&amp;name=__new__">Create trigger</a></div></div><?php
}

function render_indexes(mysqli $db,string $table,array $indexes,array $columns): void {
  $grouped=[]; foreach($indexes as $row){$grouped[$row['Key_name']][]=$row;}
  ?><div class="card mb-3"><div class="table-responsive"><table class="table mb-0"><thead><tr><th>Name</th><th>Type</th><th>Columns</th><th>Cardinality</th><th>Alter</th><th></th></tr></thead><tbody><?php foreach($grouped as $name=>$rows){?><tr><td><?= h($name) ?></td><td><?= !$rows[0]['Non_unique']?'UNIQUE ':'' ?><?= h($rows[0]['Index_type']) ?></td><td class="code"><?= h(implode(', ',array_column($rows,'Column_name'))) ?></td><td><?= h(number_format((int)$rows[0]['Cardinality'])) ?></td><td><?php if($name!=='PRIMARY'){?><form method="post" class="d-flex gap-1"><input type="hidden" name="action" value="rename_index"><input type="hidden" name="old_index_name" value="<?= h($name) ?>"><?= csrf_field() ?><input class="form-control form-control-sm" name="new_index_name" value="<?= h($name) ?>" required><button class="btn btn-secondary btn-sm">Rename</button></form><?php }?></td><td><form method="post"><input type="hidden" name="action" value="drop_index"><input type="hidden" name="index_name" value="<?= h($name) ?>"><?= csrf_field() ?><button class="btn btn-danger btn-sm" data-confirm="Drop this index?">Drop</button></form></td></tr><?php }?></tbody></table></div></div>
  <div class="card"><div class="card-header">Create index</div><div class="card-body"><form method="post"><input type="hidden" name="action" value="add_index"><?= csrf_field() ?><div class="row g-3"><div class="col-md-3"><label class="form-label">Type</label><select class="form-select" name="index_type"><option>INDEX</option><option>UNIQUE</option><option>FULLTEXT</option><option>SPATIAL</option><option>PRIMARY</option></select></div><div class="col-md-3"><label class="form-label">Name</label><input class="form-control" name="index_name"></div><div class="col-md-6"><label class="form-label">Columns (select multiple in order)</label><select class="form-select" name="index_columns[]" multiple size="5" required><?php foreach($columns as $c){?><option value="<?= h($c['COLUMN_NAME']) ?>"><?= h($c['COLUMN_NAME']) ?></option><?php }?></select></div><div class="col-12"><button class="btn btn-primary">Create index</button></div></div></form></div></div><?php
}

function render_foreign_keys(mysqli $db,string $table,array $foreign,array $columns): void {
  $grouped=[]; foreach($foreign as $row){$grouped[$row['CONSTRAINT_NAME']][]=$row;}
  $rules=[]; foreach(db_all($db,"SELECT CONSTRAINT_NAME,UPDATE_RULE,DELETE_RULE FROM information_schema.REFERENTIAL_CONSTRAINTS WHERE CONSTRAINT_SCHEMA=DATABASE() AND TABLE_NAME=".qs($db,$table)) as $r)$rules[$r['CONSTRAINT_NAME']]=$r;
  ?><div class="card mb-3"><div class="table-responsive"><table class="table mb-0"><thead><tr><th>Name</th><th>Columns</th><th>References</th><th>Rules</th><th></th></tr></thead><tbody><?php foreach($grouped as $name=>$rows){$rule=$rules[$name]??[];?><tr><td><?= h($name) ?></td><td><?= h(implode(', ',array_column($rows,'COLUMN_NAME'))) ?></td><td><?= h($rows[0]['REFERENCED_TABLE_NAME']) ?> (<?= h(implode(', ',array_column($rows,'REFERENCED_COLUMN_NAME'))) ?>)</td><td>UPDATE <?= h($rule['UPDATE_RULE']??'') ?> / DELETE <?= h($rule['DELETE_RULE']??'') ?></td><td><form method="post"><input type="hidden" name="action" value="drop_foreign_key"><input type="hidden" name="constraint_name" value="<?= h($name) ?>"><?= csrf_field() ?><button class="btn btn-danger btn-sm" data-confirm="Drop this foreign key?">Drop</button></form></td></tr><?php }?></tbody></table></div></div>
  <?php $tables=array_column(db_all($db,"SELECT TABLE_NAME FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_TYPE='BASE TABLE' ORDER BY TABLE_NAME"),'TABLE_NAME'); ?>
  <div class="card"><div class="card-header">Create foreign key</div><div class="card-body"><form method="post"><input type="hidden" name="action" value="add_foreign_key"><?= csrf_field() ?><div class="row g-3"><div class="col-md-3"><label class="form-label">Constraint name</label><input class="form-control" name="constraint_name" required></div><div class="col-md-3"><label class="form-label">Local columns</label><select class="form-select" name="local_columns[]" multiple size="5" required><?php foreach($columns as $c){?><option><?= h($c['COLUMN_NAME']) ?></option><?php }?></select></div><div class="col-md-3"><label class="form-label">Referenced table</label><select class="form-select" name="reference_table"><?php foreach($tables as $t){?><option><?= h($t) ?></option><?php }?></select></div><div class="col-md-3"><label class="form-label">Referenced columns</label><input class="form-control" name="foreign_columns[]" placeholder="First column" required><input class="form-control mt-1" name="foreign_columns[]" placeholder="Second (optional)"><input class="form-control mt-1" name="foreign_columns[]" placeholder="Third (optional)"></div><div class="col-md-3"><label class="form-label">On update</label><select class="form-select" name="on_update"><option>RESTRICT</option><option>CASCADE</option><option>SET NULL</option><option>NO ACTION</option></select></div><div class="col-md-3"><label class="form-label">On delete</label><select class="form-select" name="on_delete"><option>RESTRICT</option><option>CASCADE</option><option>SET NULL</option><option>NO ACTION</option></select></div><div class="col-12"><button class="btn btn-primary">Create foreign key</button></div></div></form><div class="form-text mt-2">For composite keys, select local columns in order and fill the same number of referenced-column inputs.</div></div></div><?php
}

function render_checks(mysqli $db,array $checks): void {
  ?><div class="card mb-3"><div class="table-responsive"><table class="table mb-0"><thead><tr><th>Name</th><th>Expression</th><th></th></tr></thead><tbody><?php foreach($checks as $check){?><tr><td><?= h($check['CONSTRAINT_NAME']) ?></td><td class="code"><?= h($check['CHECK_CLAUSE']) ?></td><td><form method="post"><input type="hidden" name="action" value="drop_check"><input type="hidden" name="constraint_name" value="<?= h($check['CONSTRAINT_NAME']) ?>"><?= csrf_field() ?><button class="btn btn-danger btn-sm" data-confirm="Drop this check constraint?">Drop</button></form></td></tr><?php }?></tbody></table></div></div><div class="card"><div class="card-header">Create check constraint</div><div class="card-body"><form method="post" class="row g-3"><input type="hidden" name="action" value="add_check"><?= csrf_field() ?><div class="col-md-4"><label class="form-label">Name</label><input class="form-control" name="constraint_name" required></div><div class="col-md-8"><label class="form-label">Expression</label><input class="form-control code" name="expression" placeholder="price >= 0" required></div><div class="col"><button class="btn btn-primary">Create check</button></div></form></div></div><?php
}

function render_partitions(mysqli $db,string $table): void {
  $parts=db_all($db,'SELECT PARTITION_NAME,PARTITION_METHOD,PARTITION_EXPRESSION,PARTITION_DESCRIPTION,TABLE_ROWS,DATA_LENGTH FROM information_schema.PARTITIONS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='.qs($db,$table).' AND PARTITION_NAME IS NOT NULL ORDER BY PARTITION_ORDINAL_POSITION');
  ?><div class="card mb-3"><div class="table-responsive"><table class="table mb-0"><thead><tr><th>Name</th><th>Method</th><th>Expression</th><th>Description</th><th>Rows</th><th>Size</th></tr></thead><tbody><?php foreach($parts as $part){?><tr><td><?= h($part['PARTITION_NAME']) ?></td><td><?= h($part['PARTITION_METHOD']) ?></td><td class="code"><?= h($part['PARTITION_EXPRESSION']) ?></td><td><?= h($part['PARTITION_DESCRIPTION']) ?></td><td><?= h($part['TABLE_ROWS']) ?></td><td><?= h(number_format((int)$part['DATA_LENGTH']/1024,1)) ?> KB</td></tr><?php }?></tbody></table></div></div><div class="card"><div class="card-header">Partition SQL</div><div class="card-body"><p class="text-body-secondary">Create, reorganize, truncate, exchange or remove partitions using a complete <code>ALTER TABLE</code> clause.</p><form method="post"><input type="hidden" name="action" value="generic_sql"><?= csrf_field() ?><textarea class="form-control sql-editor" name="statement">ALTER TABLE <?= h(qi($table)) ?> PARTITION BY RANGE (YEAR(created_at)) (
  PARTITION p2025 VALUES LESS THAN (2026),
  PARTITION pmax VALUES LESS THAN MAXVALUE
);</textarea><button class="btn btn-primary mt-2">Execute partition statement</button></form></div></div><?php
}

function render_table_settings(mysqli $db,string $table,?array $status): void {
  ?><div class="card mb-3"><div class="card-body"><form method="post"><input type="hidden" name="action" value="alter_table"><?= csrf_field() ?><div class="row g-3"><div class="col-md-4"><label class="form-label">Name</label><input class="form-control" name="name" value="<?= h($table) ?>"></div><div class="col-md-2"><label class="form-label">Engine</label><input class="form-control" name="engine" value="<?= h($status['Engine']??'InnoDB') ?>"></div><div class="col-md-3"><label class="form-label">Collation</label><input class="form-control" name="collation" value="<?= h($status['Collation']??'') ?>"></div><div class="col-md-3"><label class="form-label">Next auto increment</label><input class="form-control" type="number" name="auto_increment" value="<?= h($status['Auto_increment']??'') ?>"></div><div class="col-12"><label class="form-label">Comment</label><input class="form-control" name="comment" value="<?= h($status['Comment']??'') ?>"></div><div class="col"><button class="btn btn-primary">Save table</button></div></div></form></div></div>
  <div class="card danger-zone"><div class="card-body"><h3 class="h5 text-danger">Danger zone</h3><div class="d-flex flex-wrap gap-2"><form method="post"><input type="hidden" name="action" value="truncate_table"><?= csrf_field() ?><button class="btn btn-danger" data-confirm="Delete every row but keep the table?">Empty table</button></form><form method="post" class="d-flex gap-2"><input type="hidden" name="action" value="drop_table"><?= csrf_field() ?><input class="form-control" name="confirm_name" placeholder="Type <?= h($table) ?>" required><button class="btn btn-danger text-nowrap" data-confirm="Permanently drop this table?">Drop table</button></form></div></div></div><?php
}

function build_select_query(mysqli $db,string $table,array $columns): array {
  $allowed=array_column($columns,'COLUMN_NAME');
  $where=[]; $filterCols=$_GET['filter_col']??[]; $filterOps=$_GET['filter_op']??[]; $filterValues=$_GET['filter_val']??[];
  if(!is_array($filterCols))$filterCols=[]; if(!is_array($filterOps))$filterOps=[]; if(!is_array($filterValues))$filterValues=[];
  $operators=['='=>'=','!='=>'<>','>'=>'>','>='=>'>=','<'=>'<','<='=>'<=','contains'=>'LIKE','starts'=>'LIKE','ends'=>'LIKE','null'=>'IS NULL','not_null'=>'IS NOT NULL','regexp'=>'REGEXP','fulltext'=>'MATCH'];
  foreach($filterCols as $i=>$column){$column=(string)$column;if(!in_array($column,$allowed,true))continue;$op=(string)($filterOps[$i]??'=');if(!isset($operators[$op]))continue;$sqlOp=$operators[$op];if(in_array($op,['null','not_null'],true)){$where[]=qi($column).' '.$sqlOp;continue;}$value=(string)($filterValues[$i]??'');if($op==='fulltext'){$where[]='MATCH('.qi($column).') AGAINST ('.qs($db,$value).' IN BOOLEAN MODE)';continue;}if($op==='contains')$value='%'.$value.'%';if($op==='starts')$value=$value.'%';if($op==='ends')$value='%'.$value;$where[]=qi($column).' '.$sqlOp.' '.qs($db,$value);}
  $aggregate=strtoupper(g('aggregate'));$aggregateColumn=g('aggregate_column');$groupColumn=g('group_column');$validAgg=['COUNT','SUM','AVG','MIN','MAX'];
  $select='*';$group='';
  if(in_array($aggregate,$validAgg,true)&&in_array($aggregateColumn,$allowed,true)){$select=($groupColumn!==''&&in_array($groupColumn,$allowed,true)?qi($groupColumn).', ':'').$aggregate.'('.qi($aggregateColumn).') AS '.qi(strtolower($aggregate).'_'.$aggregateColumn);if($groupColumn!==''&&in_array($groupColumn,$allowed,true))$group=' GROUP BY '.qi($groupColumn);}
  $orderParts=[];$orderCols=$_GET['order_col']??[];$orderDirs=$_GET['order_dir']??[];if(!is_array($orderCols))$orderCols=[];if(!is_array($orderDirs))$orderDirs=[];foreach($orderCols as $i=>$column){if(in_array($column,$allowed,true))$orderParts[]=qi((string)$column).' '.(strtoupper((string)($orderDirs[$i]??'ASC'))==='DESC'?'DESC':'ASC');}
  $limit=max(1,min(500,(int)g('limit',(string)MS_ROWS_PER_PAGE)));$page=max(1,(int)g('p','1'));$offset=($page-1)*$limit;
  $from=' FROM '.qi($table).($where?' WHERE '.implode(' AND ',$where):'');
  $sql='SELECT '.$select.$from.$group.($orderParts?' ORDER BY '.implode(', ',$orderParts):'').' LIMIT '.$offset.','.$limit;
  $countSql=$group!==''?'SELECT COUNT(*) AS n FROM (SELECT 1'.$from.$group.') ms_groups':'SELECT COUNT(*) AS n'.$from;
  return [$sql,$countSql,$limit,$page,$where,$aggregate!==''&&in_array($aggregate,$validAgg,true)];
}

function page_select(mysqli $db): void {
  $table=g('table');if(!table_exists($db,$table))throw new RuntimeException('Table or view not found.');$columns=table_columns($db,$table);$meta=db_one($db,'SELECT TABLE_TYPE FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='.qs($db,$table));$editable=($meta['TABLE_TYPE']??'')==='BASE TABLE';
  $relations=[];foreach(db_all($db,"SELECT COLUMN_NAME,REFERENCED_TABLE_NAME,REFERENCED_COLUMN_NAME FROM information_schema.KEY_COLUMN_USAGE WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=".qs($db,$table)." AND REFERENCED_TABLE_NAME IS NOT NULL") as $relation){$relations[$relation['COLUMN_NAME']]=$relation;}
  [$sql,$countSql,$limit,$page,$where,$aggregated]=build_select_query($db,$table,$columns);$rows=db_all($db,$sql);$totalRow=db_one($db,$countSql);$total=(int)($totalRow['n']??0);$pages=max(1,(int)ceil($total/$limit));
  $actions='<a class="btn btn-secondary" href="?page=structure&amp;table='.urlencode($table).'">Structure</a> ';if($editable)$actions.='<a class="btn btn-primary" href="?page=row&amp;mode=insert&amp;table='.urlencode($table).'"><i class="fa-solid fa-plus me-1"></i>Insert row</a>';
  title_bar($table,number_format($total).' result(s)',$actions);
  ?><div class="card mb-3 no-print"><div class="card-header"><button class="btn btn-sm btn-secondary" data-bs-toggle="collapse" data-bs-target="#queryBuilder"><i class="fa-solid fa-filter me-1"></i>Search, aggregate, sort and limit</button></div><div class="collapse <?= $where||g('aggregate')!==''?'show':'' ?>" id="queryBuilder"><div class="card-body"><form method="get"><input type="hidden" name="page" value="select"><input type="hidden" name="table" value="<?= h($table) ?>"><h3 class="h6">Filters</h3><?php for($i=0;$i<3;$i++){?><div class="row g-2 mb-2"><div class="col-md-3"><select class="form-select" name="filter_col[]"><option value="">Column…</option><?php foreach($columns as $c){$name=$c['COLUMN_NAME'];?><option value="<?= h($name) ?>"<?= (($_GET['filter_col'][$i]??'')===$name)?' selected':'' ?>><?= h($name) ?></option><?php }?></select></div><div class="col-md-2"><select class="form-select" name="filter_op[]"><?php foreach(['=','!=','>','>=','<','<=','contains','starts','ends','regexp','fulltext','null','not_null'] as $op){?><option<?= (($_GET['filter_op'][$i]??'')===$op)?' selected':'' ?>><?= h($op) ?></option><?php }?></select></div><div class="col-md-7"><input class="form-control" name="filter_val[]" value="<?= h($_GET['filter_val'][$i]??'') ?>"></div></div><?php }?><hr><div class="row g-2"><div class="col-md-2"><label class="form-label">Aggregate</label><select class="form-select" name="aggregate"><option value="">None</option><?php foreach(['COUNT','SUM','AVG','MIN','MAX'] as $a){?><option<?= g('aggregate')===$a?' selected':'' ?>><?= $a ?></option><?php }?></select></div><div class="col-md-3"><label class="form-label">Aggregate column</label><select class="form-select" name="aggregate_column"><?php foreach($columns as $c){?><option<?= g('aggregate_column')===$c['COLUMN_NAME']?' selected':'' ?>><?= h($c['COLUMN_NAME']) ?></option><?php }?></select></div><div class="col-md-3"><label class="form-label">Group by</label><select class="form-select" name="group_column"><option value="">None</option><?php foreach($columns as $c){?><option<?= g('group_column')===$c['COLUMN_NAME']?' selected':'' ?>><?= h($c['COLUMN_NAME']) ?></option><?php }?></select></div><div class="col-md-2"><label class="form-label">Limit</label><input class="form-control" type="number" name="limit" min="1" max="500" value="<?= h((string)$limit) ?>"></div></div><hr><h3 class="h6">Ordering</h3><?php for($i=0;$i<2;$i++){?><div class="row g-2 mb-2"><div class="col-md-4"><select class="form-select" name="order_col[]"><option value="">Column…</option><?php foreach($columns as $c){?><option<?= (($_GET['order_col'][$i]??'')===$c['COLUMN_NAME'])?' selected':'' ?>><?= h($c['COLUMN_NAME']) ?></option><?php }?></select></div><div class="col-md-2"><select class="form-select" name="order_dir[]"><option>ASC</option><option<?= (($_GET['order_dir'][$i]??'')==='DESC')?' selected':'' ?>>DESC</option></select></div></div><?php }?><button class="btn btn-primary">Run query</button> <a class="btn btn-secondary" href="?page=select&amp;table=<?= urlencode($table) ?>">Reset</a></form></div></div></div>
  <form method="post"><input type="hidden" name="action" value="delete_rows"><?= csrf_field() ?><div class="card"><div class="table-scroll"><table class="table table-sm table-striped table-hover align-middle mb-0"><thead><tr><?php if($editable&&!$aggregated){?><th><input class="form-check-input" type="checkbox" data-check-all=".row-check"></th><th>Actions</th><?php }$headers=$rows?array_keys($rows[0]):array_column($columns,'COLUMN_NAME');foreach($headers as $header){?><th><?= h($header) ?></th><?php }?></tr></thead><tbody><?php foreach($rows as $row){$identity=[];foreach(primary_columns($db,$table)?:array_column($columns,'COLUMN_NAME') as $key)$identity[$key]=$row[$key]??null;$encoded=encode_identity($identity);?><tr><?php if($editable&&!$aggregated){?><td><input class="form-check-input row-check" type="checkbox" name="row_id[]" value="<?= h($encoded) ?>"></td><td class="text-nowrap"><a class="btn btn-secondary btn-sm" href="?page=row&amp;mode=edit&amp;table=<?= urlencode($table) ?>&amp;id=<?= urlencode($encoded) ?>"><i class="fa-solid fa-pen"></i></a></td><?php }foreach($row as $name=>$value){$colMeta=null;foreach($columns as $c)if($c['COLUMN_NAME']===$name){$colMeta=$c;break;}?><td><?php if($colMeta&&preg_match('/blob|binary/i',(string)$colMeta['DATA_TYPE'])&&$value!==null){?><a href="?download=blob&amp;table=<?= urlencode($table) ?>&amp;column=<?= urlencode((string)$name) ?>&amp;id=<?= urlencode($encoded) ?>"><i class="fa-solid fa-download me-1"></i><?= h(strlen((string)$value)) ?> bytes</a><?php }elseif(isset($relations[$name])&&$value!==null){$rel=$relations[$name];$relUrl='?'.http_build_query(['page'=>'select','table'=>$rel['REFERENCED_TABLE_NAME'],'filter_col'=>[$rel['REFERENCED_COLUMN_NAME']],'filter_op'=>['='],'filter_val'=>[(string)$value]]);?><a href="<?= h($relUrl) ?>" title="Open referenced row"><?= render_value($value) ?> <i class="fa-solid fa-arrow-up-right-from-square small"></i></a><?php }else{echo render_value($value);}?></td><?php }?></tr><?php }?></tbody></table></div><?php if(!$rows){?><div class="p-4 text-center text-body-secondary">No rows.</div><?php }?></div>
  <?php if($editable&&!$aggregated){?><div class="card mt-3 no-print"><div class="card-body"><div class="row g-2 align-items-end"><div class="col-md-2"><button class="btn btn-danger" data-confirm="Delete the selected rows?">Delete selected</button></div><div class="col-md-2"><select class="form-select" name="operation" formaction="<?= h(url()) ?>"><option value="set">Set</option><option value="add">Add number</option><option value="append">Append</option><option value="prepend">Prepend</option><option value="null">Set NULL</option></select></div><div class="col-md-3"><select class="form-select" name="column"><?php foreach($columns as $c){?><option><?= h($c['COLUMN_NAME']) ?></option><?php }?></select></div><div class="col-md-3"><input class="form-control" name="bulk_value" placeholder="Bulk value"></div><div class="col-md-2"><button class="btn btn-primary" name="action" value="bulk_update">Update selected</button></div></div></div></div><?php }?></form>
  <nav class="mt-3 no-print"><ul class="pagination"><?php for($i=max(1,$page-3);$i<=min($pages,$page+3);$i++){?><li class="page-item <?= $i===$page?'active':'' ?>"><a class="page-link" href="<?= h(url(['p'=>$i])) ?>"><?= $i ?></a></li><?php }?></ul></nav><div class="small text-body-secondary code mt-2">Query: <?= h($sql) ?></div><?php
}

function page_row(mysqli $db): void {
  $table = g('table');
  if (!table_exists($db, $table)) {
    throw new RuntimeException('Table not found.');
  }
  $columns = table_columns($db, $table);
  $mode = g('mode', 'insert');
  $identity = null;
  $values = [];
  if ($mode === 'edit') {
    $identity = decode_identity(g('id'));
    if (!is_array($identity)) {
      throw new RuntimeException('Invalid row identity.');
    }
    $values = db_one($db, 'SELECT * FROM ' . qi($table) . ' WHERE ' . row_identity_where($db, $columns, $identity) . ' LIMIT 1') ?? [];
  } elseif (!empty($_SESSION['ms_clone'])) {
    $values = $_SESSION['ms_clone'];
    unset($_SESSION['ms_clone']);
    foreach ($columns as $column) {
      if (strpos((string)$column['EXTRA'], 'auto_increment') !== false) {
        $values[$column['COLUMN_NAME']] = '';
      }
    }
  }
  title_bar(($mode === 'edit' ? 'Edit' : 'Insert') . ' row: ' . $table, 'Expressions are executed as SQL; use only trusted input.');
  ?><form method="post" enctype="multipart/form-data">
    <input type="hidden" name="action" value="save_row">
    <input type="hidden" name="identity" value="<?= h($identity === null ? '' : encode_identity($identity)) ?>">
    <?= csrf_field() ?>
    <div class="card"><div class="table-responsive"><table class="table align-middle mb-0"><thead><tr><th>Column</th><th>Type</th><th>Value</th><th>Options</th></tr></thead><tbody>
    <?php foreach ($columns as $column) {
      $name = (string)$column['COLUMN_NAME'];
      $generated = strpos((string)$column['EXTRA'], 'GENERATED') !== false;
      $binary = preg_match('/blob|binary/i', (string)$column['DATA_TYPE']) === 1;
      ?><tr><td><strong><?= h($name) ?></strong><?php if ($column['COLUMN_KEY']) { ?><span class="badge text-bg-primary ms-1"><?= h($column['COLUMN_KEY']) ?></span><?php } ?></td><td class="code small"><?= h($column['COLUMN_TYPE']) ?></td><td>
      <?php if ($generated) { ?>
        <span class="text-body-secondary">Generated automatically</span>
      <?php } elseif ($binary) { ?>
        <?php if ($mode === 'edit' && array_key_exists($name, $values) && $values[$name] !== null) { ?><div class="small mb-1"><?= h(strlen((string)$values[$name])) ?> existing bytes</div><?php } ?>
        <input class="form-control mb-1" type="file" name="upload[<?= h($name) ?>]">
        <textarea class="form-control code" name="value[<?= h($name) ?>]" rows="2" placeholder="Or enter textual bytes"></textarea>
      <?php } elseif (in_array($column['DATA_TYPE'], ['text','mediumtext','longtext','json'], true)) { ?>
        <textarea class="form-control code" name="value[<?= h($name) ?>]" rows="4"><?= h($values[$name] ?? '') ?></textarea>
      <?php } elseif ($column['DATA_TYPE'] === 'enum' && preg_match_all("/'((?:[^'\\\\]|\\\\.)*)'/", (string)$column['COLUMN_TYPE'], $matches)) { ?>
        <select class="form-select" name="value[<?= h($name) ?>]"><?php foreach ($matches[1] as $option) { $option = stripcslashes($option); ?><option<?= (($values[$name] ?? '') === $option) ? ' selected' : '' ?>><?= h($option) ?></option><?php } ?></select>
      <?php } else { ?>
        <input class="form-control" name="value[<?= h($name) ?>]" value="<?= h($values[$name] ?? '') ?>">
      <?php } ?></td><td><?php if (!$generated) { ?>
        <label class="d-block"><input class="form-check-input" type="checkbox" name="is_null[<?= h($name) ?>]"> NULL</label>
        <label class="d-block"><input class="form-check-input" type="checkbox" name="expression[<?= h($name) ?>]"> SQL expression</label>
        <?php if ($binary && $mode === 'edit') { ?><label class="d-block"><input class="form-check-input" type="checkbox" name="keep_blob[<?= h($name) ?>]" checked> Keep existing</label><?php } ?>
      <?php } ?></td></tr>
    <?php } ?>
    </tbody></table></div></div>
    <div class="mt-3 d-flex gap-2"><button class="btn btn-primary">Save row</button><a class="btn btn-secondary" href="?page=select&amp;table=<?= urlencode($table) ?>">Cancel</a></div>
  </form>
  <?php if ($mode === 'edit') { ?><form method="post" class="mt-2"><input type="hidden" name="action" value="clone_row"><input type="hidden" name="identity" value="<?= h(encode_identity($identity)) ?>"><?= csrf_field() ?><button class="btn btn-secondary">Clone row</button></form><?php }
}

function page_sql(mysqli $db,?array $results,float $time): void {
  title_bar('SQL command',selected_db());
  ?><div class="card mb-3"><div class="card-body"><form method="post" enctype="multipart/form-data"><input type="hidden" name="action" value="run_sql"><?= csrf_field() ?><label class="form-label">SQL statements</label><textarea class="form-control sql-editor" name="sql" spellcheck="false"><?= h(p('sql',(string)($_SESSION['ms_last_sql']??''))) ?></textarea><div class="row g-3 mt-1 align-items-end"><div class="col-md-7"><label class="form-label">Or import a .sql file (maximum 50 MB)</label><input class="form-control" type="file" name="sql_file" accept=".sql,text/sql,text/plain"></div><div class="col-md-5 text-md-end"><button class="btn btn-primary"><i class="fa-solid fa-play me-1"></i>Execute <span class="small">Ctrl+Enter</span></button></div></div></form></div></div><?php if($results!==null)render_sql_results($results,$time);
}

function page_export(mysqli $db): void {
  $tables=db_all($db,'SELECT TABLE_NAME,TABLE_TYPE FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() ORDER BY TABLE_NAME');title_bar('Export',selected_db());
  ?><div class="card"><div class="card-body"><form method="get"><input type="hidden" name="download" value="export"><div class="row g-3"><div class="col-md-4"><label class="form-label">Format</label><select class="form-select" name="format"><option value="sql">SQL</option><option value="csv">CSV (one table only)</option></select></div><div class="col-md-8"><label class="form-label">Objects</label><select class="form-select" name="tables[]" multiple size="12"><?php foreach($tables as $t){?><option value="<?= h($t['TABLE_NAME']) ?>" selected><?= h($t['TABLE_NAME'].' · '.$t['TABLE_TYPE']) ?></option><?php }?></select><div class="form-text">Leave all selected to export the database. CSV requires exactly one selection.</div></div><div class="col-12 d-flex gap-4"><label><input class="form-check-input" type="checkbox" name="structure" value="1" checked> Structure, views, routines, triggers and events</label><label><input class="form-check-input" type="checkbox" name="data" value="1" checked> Data</label><label><input class="form-check-input" type="checkbox" name="drop" value="1" checked> Add DROP statements</label></div><div class="col"><button class="btn btn-primary"><i class="fa-solid fa-download me-1"></i>Download export</button></div></div></form></div></div><?php
}

function page_schema(mysqli $db): void {
  $tables=db_all($db,"SELECT TABLE_NAME FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_TYPE='BASE TABLE' ORDER BY TABLE_NAME");$foreign=db_all($db,"SELECT TABLE_NAME,COLUMN_NAME,REFERENCED_TABLE_NAME,REFERENCED_COLUMN_NAME,CONSTRAINT_NAME FROM information_schema.KEY_COLUMN_USAGE WHERE TABLE_SCHEMA=DATABASE() AND REFERENCED_TABLE_NAME IS NOT NULL ORDER BY TABLE_NAME,CONSTRAINT_NAME,ORDINAL_POSITION");$refs=[];foreach($foreign as $f)$refs[$f['TABLE_NAME']][$f['COLUMN_NAME']]=$f;
  title_bar('Database schema',selected_db(),'<button class="btn btn-primary" onclick="window.print()"><i class="fa-solid fa-print me-1"></i>Print</button>');
  ?><div class="schema-canvas p-2"><?php foreach($tables as $t){$name=(string)$t['TABLE_NAME'];$cols=table_columns($db,$name);?><section class="schema-table card shadow-sm"><div class="card-header fw-bold"><i class="fa-solid fa-table me-1"></i><?= h($name) ?></div><ul class="list-group list-group-flush small"><?php foreach($cols as $c){$ref=$refs[$name][$c['COLUMN_NAME']]??null;?><li class="list-group-item d-flex justify-content-between gap-2"><span><?= h($c['COLUMN_NAME']) ?><?php if($c['COLUMN_KEY']==='PRI'){?> <i class="fa-solid fa-key text-warning"></i><?php }?></span><span class="text-body-secondary"><?= h($c['COLUMN_TYPE']) ?></span><?php if($ref){?><div class="schema-line w-100"><i class="fa-solid fa-arrow-right"></i> <?= h($ref['REFERENCED_TABLE_NAME'].'.'.$ref['REFERENCED_COLUMN_NAME']) ?></div><?php }?></li><?php }?></ul></section><?php }?></div><?php
}

function object_page_data(mysqli $db,string $type): array {
  if($type==='VIEW')return db_all($db,"SELECT TABLE_NAME AS name,CHECK_OPTION AS detail,IS_UPDATABLE AS extra FROM information_schema.VIEWS WHERE TABLE_SCHEMA=DATABASE() ORDER BY TABLE_NAME");
  if(in_array($type,['PROCEDURE','FUNCTION'],true))return db_all($db,'SELECT ROUTINE_NAME AS name,DATA_TYPE AS detail,SECURITY_TYPE AS extra FROM information_schema.ROUTINES WHERE ROUTINE_SCHEMA=DATABASE() AND ROUTINE_TYPE='.qs($db,$type).' ORDER BY ROUTINE_NAME');
  if($type==='TRIGGER')return db_all($db,"SELECT TRIGGER_NAME AS name,CONCAT(ACTION_TIMING,' ',EVENT_MANIPULATION,' ON ',EVENT_OBJECT_TABLE) AS detail,ACTION_ORIENTATION AS extra FROM information_schema.TRIGGERS WHERE TRIGGER_SCHEMA=DATABASE() ORDER BY TRIGGER_NAME");
  return db_all($db,"SELECT EVENT_NAME AS name,CONCAT(EVENT_TYPE,' ',COALESCE(INTERVAL_VALUE,''),' ',COALESCE(INTERVAL_FIELD,'')) AS detail,STATUS AS extra FROM information_schema.EVENTS WHERE EVENT_SCHEMA=DATABASE() ORDER BY EVENT_NAME");
}

function page_objects(mysqli $db,string $page): void {
  $map=['views'=>['VIEW','Views'],'triggers'=>['TRIGGER','Triggers'],'events'=>['EVENT','Events']];[$type,$title]=$map[$page];$rows=object_page_data($db,$type);$name=g('name');$definition=$name!==''?raw_definition($db,$type,$name):'';$templates=['VIEW'=>'CREATE VIEW `view_name` AS\nSELECT * FROM `table_name`','TRIGGER'=>'CREATE TRIGGER `trigger_name` BEFORE INSERT ON `table_name`\nFOR EACH ROW SET NEW.created_at = CURRENT_TIMESTAMP','EVENT'=>'CREATE EVENT `event_name`\nON SCHEDULE EVERY 1 DAY\nDO DELETE FROM `logs` WHERE created_at < NOW() - INTERVAL 30 DAY'];
  title_bar($title,selected_db(),'<a class="btn btn-primary" href="?page='.h($page).'&amp;name=__new__"><i class="fa-solid fa-plus me-1"></i>Create</a>');
  ?><div class="row g-3"><div class="col-lg-5"><div class="card"><div class="table-responsive"><table class="table table-hover mb-0"><thead><tr><th>Name</th><th>Details</th><th></th></tr></thead><tbody><?php foreach($rows as $row){?><tr><td><a href="?page=<?= h($page) ?>&amp;name=<?= urlencode((string)$row['name']) ?>"><?= h($row['name']) ?></a></td><td><?= h($row['detail'].' '.$row['extra']) ?></td><td><?php if($type==='VIEW'){?><a class="btn btn-secondary btn-sm" href="?page=select&amp;table=<?= urlencode((string)$row['name']) ?>">Select</a><?php }?></td></tr><?php }?></tbody></table></div></div></div><div class="col-lg-7"><?php if($name!==''){if($name==='__new__')$definition=$templates[$type];?><div class="card"><div class="card-header"><?= $name==='__new__'?'Create':'Alter' ?> <?= h(strtolower($type)) ?></div><div class="card-body"><form method="post"><input type="hidden" name="action" value="save_object"><input type="hidden" name="kind" value="<?= h($type) ?>"><input type="hidden" name="old_name" value="<?= h($name==='__new__'?'':$name) ?>"><?= csrf_field() ?><textarea class="form-control sql-editor" name="definition" required><?= h($definition) ?></textarea><div class="mt-2 d-flex gap-2"><button class="btn btn-primary">Save</button></form><?php if($name!=='__new__'){?><form method="post"><input type="hidden" name="action" value="drop_object"><input type="hidden" name="kind" value="<?= h($type) ?>"><input type="hidden" name="name" value="<?= h($name) ?>"><?= csrf_field() ?><button class="btn btn-danger" data-confirm="Drop this object?">Drop</button></form><?php }?></div></div></div><?php }else{?><div class="alert alert-info">Select an object to inspect or alter it.</div><?php }?></div></div><?php
}

function page_routines(mysqli $db): void {
  $rows=db_all($db,"SELECT ROUTINE_NAME,ROUTINE_TYPE,DATA_TYPE,SECURITY_TYPE FROM information_schema.ROUTINES WHERE ROUTINE_SCHEMA=DATABASE() ORDER BY ROUTINE_TYPE,ROUTINE_NAME");$name=g('name');$kind=strtoupper(g('kind','PROCEDURE'));$definition=$name!==''?raw_definition($db,$kind,$name):'';
  title_bar('Stored routines',selected_db(),'<a class="btn btn-primary" href="?page=routines&amp;name=__new__&amp;kind=PROCEDURE">Create procedure</a> <a class="btn btn-secondary" href="?page=routines&amp;name=__new__&amp;kind=FUNCTION">Create function</a>');
  ?><div class="row g-3"><div class="col-lg-5"><div class="card"><table class="table mb-0"><thead><tr><th>Name</th><th>Type</th><th>Returns</th></tr></thead><tbody><?php foreach($rows as $r){?><tr><td><a href="?page=routines&amp;name=<?= urlencode((string)$r['ROUTINE_NAME']) ?>&amp;kind=<?= h($r['ROUTINE_TYPE']) ?>"><?= h($r['ROUTINE_NAME']) ?></a></td><td><?= h($r['ROUTINE_TYPE']) ?></td><td><?= h($r['DATA_TYPE']) ?></td></tr><?php }?></tbody></table></div></div><div class="col-lg-7"><?php if($name!==''){if($name==='__new__')$definition=$kind==='FUNCTION'?"CREATE FUNCTION `function_name` (`value` INT)\nRETURNS INT DETERMINISTIC\nRETURN `value` * 2":"CREATE PROCEDURE `procedure_name` (IN `value` INT)\nBEGIN\n  SELECT `value`;\nEND";?><div class="card mb-3"><div class="card-header"><?= $name==='__new__'?'Create':'Alter' ?> <?= h(strtolower($kind)) ?></div><div class="card-body"><form method="post"><input type="hidden" name="action" value="save_object"><input type="hidden" name="kind" value="<?= h($kind) ?>"><input type="hidden" name="old_name" value="<?= h($name==='__new__'?'':$name) ?>"><?= csrf_field() ?><textarea class="form-control sql-editor" name="definition"><?= h($definition) ?></textarea><button class="btn btn-primary mt-2">Save</button></form></div></div><?php if($name!=='__new__'){$params=db_all($db,"SELECT PARAMETER_NAME,PARAMETER_MODE,DTD_IDENTIFIER FROM information_schema.PARAMETERS WHERE SPECIFIC_SCHEMA=DATABASE() AND SPECIFIC_NAME=".qs($db,$name)." AND PARAMETER_MODE IS NOT NULL ORDER BY ORDINAL_POSITION");?><div class="card"><div class="card-header">Call routine</div><div class="card-body"><form method="post"><input type="hidden" name="action" value="call_routine"><input type="hidden" name="kind" value="<?= h($kind) ?>"><input type="hidden" name="name" value="<?= h($name) ?>"><?= csrf_field() ?><?php foreach($params as $param){?><label class="form-label"><?= h($param['PARAMETER_MODE'].' '.$param['PARAMETER_NAME'].' '.$param['DTD_IDENTIFIER']) ?></label><input class="form-control mb-2" name="arg[]"><?php }?><button class="btn btn-primary">Call</button></form></div></div><?php }}else{?><div class="alert alert-info">Select a routine to alter or call it.</div><?php }?></div></div><?php
}

function page_processes(mysqli $db): void {
  $rows=db_all($db,'SHOW FULL PROCESSLIST');title_bar('Server processes',count($rows).' active process(es)','<a class="btn btn-primary" href="?page=processes"><i class="fa-solid fa-rotate me-1"></i>Refresh</a>');
  ?><div class="card"><div class="table-scroll"><table class="table table-sm table-striped align-middle mb-0"><thead><tr><th>ID</th><th>User</th><th>Host</th><th>DB</th><th>Command</th><th>Time</th><th>State</th><th>Info</th><th></th></tr></thead><tbody><?php foreach($rows as $r){?><tr><td><?= h($r['Id']) ?></td><td><?= h($r['User']) ?></td><td><?= h($r['Host']) ?></td><td><?= h($r['db']) ?></td><td><?= h($r['Command']) ?></td><td><?= h($r['Time']) ?></td><td><?= h($r['State']) ?></td><td><?= render_value($r['Info'],300) ?></td><td><form method="post"><input type="hidden" name="action" value="kill_process"><input type="hidden" name="process_id" value="<?= h($r['Id']) ?>"><?= csrf_field() ?><button class="btn btn-danger btn-sm" data-confirm="Kill this database process?">Kill</button></form></td></tr><?php }?></tbody></table></div></div><?php
}

function page_variables(mysqli $db): void {
  $kind=g('kind','variables');$rows=$kind==='status'?db_all($db,'SHOW GLOBAL STATUS'):db_all($db,'SHOW GLOBAL VARIABLES');$filter=strtolower(g('q'));if($filter!=='')$rows=array_values(array_filter($rows,static function($r)use($filter){return strpos(strtolower(implode(' ',array_map('strval',$r))),$filter)!==false;}));
  title_bar('Server variables & status',server_version($db));
  ?><div class="card mb-3 no-print"><div class="card-body"><form method="get" class="row g-2"><input type="hidden" name="page" value="variables"><div class="col-md-3"><select class="form-select" name="kind"><option value="variables"<?= $kind==='variables'?' selected':'' ?>>Variables</option><option value="status"<?= $kind==='status'?' selected':'' ?>>Status</option></select></div><div class="col-md-7"><input class="form-control" name="q" value="<?= h(g('q')) ?>" placeholder="Filter name or value"></div><div class="col-md-2"><button class="btn btn-primary w-100">Filter</button></div></form></div></div><div class="card"><div class="table-responsive"><table class="table table-sm table-striped mb-0"><thead><tr><th>Name</th><th>Value</th><th>Documentation</th></tr></thead><tbody><?php foreach($rows as $r){$values=array_values($r);$name=(string)($values[0]??'');?><tr><td class="code"><?= h($name) ?></td><td><?= render_value($values[1]??'') ?></td><td><a target="_blank" rel="noopener" href="https://dev.mysql.com/doc/refman/8.4/en/server-system-variables.html#sysvar_<?= urlencode(strtolower($name)) ?>"><i class="fa-solid fa-arrow-up-right-from-square"></i></a></td></tr><?php }?></tbody></table></div></div><?php
}

function page_users(mysqli $db): void {
  $rows=[];try{$rows=db_all($db,'SELECT User,Host,plugin,account_locked,password_expired FROM mysql.user ORDER BY User,Host');}catch(Throwable $ignored){$rows=db_all($db,'SELECT User,Host FROM mysql.user ORDER BY User,Host');}
  title_bar('Users & privileges',count($rows).' account(s)');
  ?><div class="card mb-3"><div class="table-responsive"><table class="table table-hover align-middle mb-0"><thead><tr><th>User</th><th>Host</th><th>Plugin</th><th>Status</th><th>Rights</th><th></th></tr></thead><tbody><?php foreach($rows as $r){$grants=[];try{$grants=db_all($db,'SHOW GRANTS FOR '.qs($db,$r['User']).'@'.qs($db,$r['Host']));}catch(Throwable $ignored){}?><tr><td><?= h($r['User']) ?></td><td><?= h($r['Host']) ?></td><td><?= h($r['plugin']??'') ?></td><td><?= h(($r['account_locked']??'').' '.($r['password_expired']??'')) ?></td><td class="small code"><?php foreach($grants as $grant)echo h((string)array_values($grant)[0]).'<br>';?></td><td><form method="post"><input type="hidden" name="action" value="drop_user"><input type="hidden" name="drop_user" value="<?= h($r['User']) ?>"><input type="hidden" name="drop_host" value="<?= h($r['Host']) ?>"><?= csrf_field() ?><button class="btn btn-danger btn-sm" data-confirm="Drop this user account?">Drop</button></form></td></tr><?php }?></tbody></table></div></div>
  <div class="row g-3"><div class="col-lg-5"><div class="card mb-3"><div class="card-header">Create user</div><div class="card-body"><form method="post"><input type="hidden" name="action" value="create_user"><?= csrf_field() ?><label class="form-label">Username</label><input class="form-control mb-2" name="new_user" required><label class="form-label">Host</label><input class="form-control mb-2" name="new_host" value="%" required><label class="form-label">Password</label><input class="form-control mb-2" type="password" name="new_password" required><button class="btn btn-primary">Create user</button></form></div></div><div class="card"><div class="card-header">Change password / account state</div><div class="card-body"><form method="post"><input type="hidden" name="action" value="alter_user"><?= csrf_field() ?><label class="form-label">Username</label><input class="form-control mb-2" name="alter_user" required><label class="form-label">Host</label><input class="form-control mb-2" name="alter_host" value="%" required><label class="form-label">New password (optional)</label><input class="form-control mb-2" type="password" name="alter_password"><label class="form-label">Account state</label><select class="form-select mb-2" name="lock_mode"><option value="">No change</option><option value="lock">Lock</option><option value="unlock">Unlock</option></select><button class="btn btn-primary">Update user</button></form></div></div></div><div class="col-lg-7"><div class="card"><div class="card-header">Grant or revoke privileges</div><div class="card-body"><form method="post"><input type="hidden" name="action" value="grant_privileges"><?= csrf_field() ?><div class="row g-2"><div class="col-md-4"><label class="form-label">Operation</label><select class="form-select" name="privilege_mode"><option value="grant">Grant</option><option value="revoke">Revoke</option></select></div><div class="col-md-4"><label class="form-label">User</label><input class="form-control" name="grant_user" required></div><div class="col-md-4"><label class="form-label">Host</label><input class="form-control" name="grant_host" value="%" required></div><div class="col-md-6"><label class="form-label">Scope</label><select class="form-select" name="scope"><option value="database">Database</option><option value="global">Global</option></select></div><div class="col-md-6"><label class="form-label">Database</label><input class="form-control" name="grant_database" value="<?= h(selected_db()) ?>"></div><div class="col-12"><label class="form-label">Privileges</label><div class="d-flex flex-wrap gap-3"><?php foreach(['ALL PRIVILEGES','SELECT','INSERT','UPDATE','DELETE','CREATE','DROP','ALTER','INDEX','REFERENCES','EXECUTE','CREATE VIEW','SHOW VIEW','TRIGGER','EVENT','CREATE ROUTINE','ALTER ROUTINE'] as $priv){?><label><input class="form-check-input" type="checkbox" name="privilege[]" value="<?= h($priv) ?>"> <?= h($priv) ?></label><?php }?></div></div><div class="col-12"><label><input class="form-check-input" type="checkbox" name="grant_option"> WITH GRANT OPTION</label></div><div class="col"><button class="btn btn-primary">Apply privileges</button></div></div></form></div></div></div></div><?php
}

if (empty($_SESSION['ms_login'])) {
  page_login($error);
  exit;
}

try {
  $db = connect_db(false);
  $page = g('page', selected_db() !== '' ? 'database' : 'databases');
  $allowedPages = ['databases','database','create_table','structure','select','row','sql','export','schema','views','routines','triggers','events','processes','users','variables'];
  if (!in_array($page, $allowedPages, true)) {
    $page = selected_db() !== '' ? 'database' : 'databases';
  }
  $needsDatabase = !in_array($page, ['databases','processes','users','variables'], true);
  if ($needsDatabase) {
    if (selected_db() === '') {
      go(['page' => 'databases'], 'Choose a database first.', 'warning');
    }
    if (!$db->select_db(selected_db())) {
      throw new RuntimeException($db->error);
    }
  }
  page_head(ucwords(str_replace('_',' ',$page)), true);
  $layoutStarted = true;
  echo flash();
  if ($error !== '') {
    echo '<div class="alert alert-danger">' . h($error) . '</div>';
  }
  switch ($page) {
    case 'databases': page_databases($db); break;
    case 'database': page_database($db); break;
    case 'create_table': page_create_table($db); break;
    case 'structure': page_structure($db); break;
    case 'select': page_select($db); break;
    case 'row': page_row($db); break;
    case 'sql': page_sql($db, isset($sqlResults) ? $sqlResults : null, isset($sqlTime) ? (float)$sqlTime : 0.0); break;
    case 'export': page_export($db); break;
    case 'schema': page_schema($db); break;
    case 'views': page_objects($db, 'views'); break;
    case 'routines': page_routines($db); if(isset($sqlResults)) render_sql_results($sqlResults,(float)$sqlTime); break;
    case 'triggers': page_objects($db, 'triggers'); break;
    case 'events': page_objects($db, 'events'); break;
    case 'processes': page_processes($db); break;
    case 'users': page_users($db); break;
    case 'variables': page_variables($db); break;
  }
  page_foot();
} catch (Throwable $e) {
  if (!headers_sent()) {
    http_response_code(500);
  }
  if (!$layoutStarted) {
    page_head('Error', true);
    $layoutStarted = true;
  }
  echo '<div class="alert alert-danger"><h1 class="h5">Operation failed</h1>' . h($e->getMessage()) . '</div><a class="btn btn-secondary" href="?page=databases">Back to databases</a>';
  page_foot();
}
