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
const MS_VERSION = '1.8.0';
const MS_ROWS_PER_PAGE = 50;
const MS_SQL_ROWS_DEFAULT = 1000;
const MS_MAX_CELL_BYTES = 100000;

// Automatic self-update from the public GitHub repository.
const MS_UPDATE_URL = 'https://raw.githubusercontent.com/ziobit/adminerclone/main/index.php';
const MS_UPDATE_CHECK_SECONDS = 21600; // 6 hours, server-wide.
const MS_UPDATE_MAX_BYTES = 5242880; // Refuse unexpectedly large downloads (5 MB).

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

function browser_setting_int(string $cookie, int $default, int $minimum, int $maximum): int {
  if (!isset($_COOKIE[$cookie]) || is_array($_COOKIE[$cookie]) || preg_match('/\A\d+\z/', (string)$_COOKIE[$cookie]) !== 1) {
    return $default;
  }
  return max($minimum, min($maximum, (int)$_COOKIE[$cookie]));
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

/**
 * Return a private runtime filename for the updater.
 *
 * Cache, lock and backup files are deliberately stored in the system temporary
 * directory instead of next to index.php so they are not normally web-accessible.
 */
function ms_update_runtime_file(string $suffix): string {
  $identity = realpath(__FILE__);
  if ($identity === false) {
    $identity = __FILE__;
  }
  $directory = rtrim(sys_get_temp_dir(), DIRECTORY_SEPARATOR);
  return $directory . DIRECTORY_SEPARATOR . 'mysql-studio-' . sha1($identity) . '-' . $suffix;
}

function ms_update_cache_read(): array {
  $raw = @file_get_contents(ms_update_runtime_file('update.json'));
  if (!is_string($raw) || $raw === '') {
    return [];
  }
  $decoded = json_decode($raw, true);
  return is_array($decoded) ? $decoded : [];
}

function ms_update_cache_write(array $cache): void {
  $json = json_encode($cache, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
  if (!is_string($json)) {
    return;
  }
  @file_put_contents(ms_update_runtime_file('update.json'), $json, LOCK_EX);
}

function ms_update_set_notice(string $key, string $message, string $type = 'info'): void {
  if (!isset($_SESSION['ms_update_notice_seen']) || !is_array($_SESSION['ms_update_notice_seen'])) {
    $_SESSION['ms_update_notice_seen'] = [];
  }
  if (!empty($_SESSION['ms_update_notice_seen'][$key])) {
    return;
  }
  $_SESSION['ms_update_notice_seen'][$key] = true;
  $_SESSION['ms_update_notice'] = [$type, $message];
}

function ms_update_notice(): string {
  if (empty($_SESSION['ms_update_notice']) || !is_array($_SESSION['ms_update_notice'])) {
    return '';
  }
  $notice = $_SESSION['ms_update_notice'];
  unset($_SESSION['ms_update_notice']);
  $type = (string)($notice[0] ?? 'info');
  if (!in_array($type, ['info', 'success', 'warning', 'danger'], true)) {
    $type = 'info';
  }
  $message = (string)($notice[1] ?? '');
  if ($message === '') {
    return '';
  }
  return '<div class="alert alert-' . h($type) . ' alert-dismissible fade show" role="alert"><i class="fa-solid fa-cloud-arrow-down me-2"></i>' . h($message) . '<button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button></div>';
}

function ms_update_extract_version(string $source): ?string {
  if (preg_match('/\bconst\s+MS_VERSION\s*=\s*[\'\"]([^\'\"]+)[\'\"]\s*;/', $source, $match) !== 1) {
    return null;
  }
  $version = trim((string)$match[1]);
  return $version !== '' ? $version : null;
}

function ms_update_download(): ?string {
  $url = MS_UPDATE_URL;

  if (function_exists('curl_init')) {
    $ch = curl_init($url);
    if ($ch !== false) {
      curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_MAXREDIRS => 3,
        CURLOPT_CONNECTTIMEOUT => 5,
        CURLOPT_TIMEOUT => 20,
        CURLOPT_USERAGENT => MS_APP_NAME . '/' . MS_VERSION,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_SSL_VERIFYHOST => 2,
        CURLOPT_HTTPHEADER => ['Accept: text/plain', 'Cache-Control: no-cache']
      ]);
      $source = curl_exec($ch);
      $status = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
      curl_close($ch);
      if (is_string($source) && $status >= 200 && $status < 300 && strlen($source) <= MS_UPDATE_MAX_BYTES) {
        return $source;
      }
    }
  }

  if (filter_var(ini_get('allow_url_fopen'), FILTER_VALIDATE_BOOLEAN)) {
    $context = stream_context_create([
      'http' => [
        'method' => 'GET',
        'timeout' => 20,
        'follow_location' => 1,
        'max_redirects' => 3,
        'ignore_errors' => false,
        'header' => "User-Agent: " . MS_APP_NAME . '/' . MS_VERSION . "\r\nAccept: text/plain\r\nCache-Control: no-cache\r\n"
      ],
      'ssl' => [
        'verify_peer' => true,
        'verify_peer_name' => true
      ]
    ]);
    $source = @file_get_contents($url, false, $context);
    if (is_string($source) && strlen($source) <= MS_UPDATE_MAX_BYTES) {
      return $source;
    }
  }

  return null;
}

function ms_update_validate_source(string $source, string $expectedVersion): ?string {
  if ($source === '' || strlen($source) < 20000) {
    return 'The downloaded update is incomplete.';
  }
  if (strlen($source) > MS_UPDATE_MAX_BYTES) {
    return 'The downloaded update is unexpectedly large.';
  }
  if (strncmp($source, '<?php', 5) !== 0) {
    return 'The downloaded file is not a valid MySQL Studio PHP file.';
  }

  $requiredMarkers = [
    "const MS_APP_NAME = 'MySQL Studio';",
    'function connect_db(',
    'function page_head(',
    'function page_foot(',
    'function render_sidebar(',
    'function ms_auto_update('
  ];
  foreach ($requiredMarkers as $marker) {
    if (strpos($source, $marker) === false) {
      return 'The downloaded file failed the MySQL Studio integrity check.';
    }
  }

  $version = ms_update_extract_version($source);
  if ($version === null || $version !== $expectedVersion) {
    return 'The downloaded file does not contain the expected version.';
  }

  try {
    token_get_all($source, TOKEN_PARSE);
  } catch (Throwable $e) {
    return 'The downloaded update contains invalid PHP syntax: ' . $e->getMessage();
  }

  return null;
}

function ms_update_install(string $source, string $remoteVersion): ?string {
  $currentFile = __FILE__;
  $directory = dirname($currentFile);

  if (!is_writable($currentFile)) {
    return basename($currentFile) . ' is not writable by PHP.';
  }
  if (!is_writable($directory)) {
    return 'The directory containing ' . basename($currentFile) . ' is not writable by PHP.';
  }

  $validationError = ms_update_validate_source($source, $remoteVersion);
  if ($validationError !== null) {
    return $validationError;
  }

  $temporaryFile = @tempnam($directory, '.mysql-studio-update-');
  if (!is_string($temporaryFile) || $temporaryFile === '') {
    return 'Unable to create the temporary update file.';
  }

  $written = @file_put_contents($temporaryFile, $source, LOCK_EX);
  if ($written === false || $written !== strlen($source)) {
    @unlink($temporaryFile);
    return 'Unable to write the complete temporary update file.';
  }

  $permissions = @fileperms($currentFile);
  if ($permissions !== false) {
    @chmod($temporaryFile, $permissions & 0777);
  }

  $temporarySource = @file_get_contents($temporaryFile);
  if (!is_string($temporarySource) || !hash_equals(hash('sha256', $source), hash('sha256', $temporarySource))) {
    @unlink($temporaryFile);
    return 'The temporary update file failed its checksum verification.';
  }

  $backupFile = ms_update_runtime_file('backup.php');
  if (!@copy($currentFile, $backupFile)) {
    @unlink($temporaryFile);
    return 'Unable to create a rollback backup of the current version.';
  }

  $replaced = @rename($temporaryFile, $currentFile);

  // On platforms where rename() cannot replace an existing file, use the
  // rollback copy to make the fallback replacement safe.
  if (!$replaced) {
    if (@unlink($currentFile)) {
      $replaced = @rename($temporaryFile, $currentFile);
    }
  }

  if (!$replaced) {
    @copy($backupFile, $currentFile);
    @unlink($temporaryFile);
    return 'The update could not replace the current file. The previous version has been restored.';
  }

  clearstatcache(true, $currentFile);
  $installed = @file_get_contents($currentFile);
  if (!is_string($installed) || !hash_equals(hash('sha256', $source), hash('sha256', $installed))) {
    @copy($backupFile, $currentFile);
    return 'The installed file failed verification. The previous version has been restored.';
  }

  return null;
}

function ms_auto_update(): void {
  if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'GET') {
    return;
  }
  if (isset($_GET['download'])) {
    return;
  }

  $now = time();
  $cache = ms_update_cache_read();
  $checkedAt = (int)($cache['checked_at'] ?? 0);

  if ($checkedAt > 0 && ($now - $checkedAt) < MS_UPDATE_CHECK_SECONDS) {
    $cachedRemoteVersion = (string)($cache['remote_version'] ?? '');
    if (($cache['status'] ?? '') === 'install_failed' && $cachedRemoteVersion !== '' && version_compare($cachedRemoteVersion, MS_VERSION, '>')) {
      $reason = trim((string)($cache['message'] ?? 'Automatic installation failed.'));
      ms_update_set_notice(
        'update-failed-' . $cachedRemoteVersion,
        MS_APP_NAME . ' ' . $cachedRemoteVersion . ' is available, but the automatic update could not be installed: ' . $reason,
        'warning'
      );
    }
    return;
  }

  $lock = @fopen(ms_update_runtime_file('update.lock'), 'c');
  if (!is_resource($lock)) {
    return;
  }
  if (!@flock($lock, LOCK_EX | LOCK_NB)) {
    fclose($lock);
    return;
  }

  try {
    // Another request may have completed the check just before this request
    // acquired the lock, so check the cache again.
    $cache = ms_update_cache_read();
    $checkedAt = (int)($cache['checked_at'] ?? 0);
    if ($checkedAt > 0 && ($now - $checkedAt) < MS_UPDATE_CHECK_SECONDS) {
      return;
    }

    $source = ms_update_download();
    if ($source === null) {
      ms_update_cache_write([
        'checked_at' => $now,
        'local_version' => MS_VERSION,
        'remote_version' => '',
        'status' => 'check_failed',
        'message' => 'GitHub could not be reached.'
      ]);
      return;
    }

    $remoteVersion = ms_update_extract_version($source);
    if ($remoteVersion === null) {
      ms_update_cache_write([
        'checked_at' => $now,
        'local_version' => MS_VERSION,
        'remote_version' => '',
        'status' => 'check_failed',
        'message' => 'The remote version could not be determined.'
      ]);
      return;
    }

    if (!version_compare($remoteVersion, MS_VERSION, '>')) {
      ms_update_cache_write([
        'checked_at' => $now,
        'local_version' => MS_VERSION,
        'remote_version' => $remoteVersion,
        'status' => 'current',
        'message' => ''
      ]);
      return;
    }

    $installError = ms_update_install($source, $remoteVersion);
    if ($installError !== null) {
      ms_update_cache_write([
        'checked_at' => $now,
        'local_version' => MS_VERSION,
        'remote_version' => $remoteVersion,
        'status' => 'install_failed',
        'message' => $installError
      ]);
      ms_update_set_notice(
        'update-failed-' . $remoteVersion,
        MS_APP_NAME . ' ' . $remoteVersion . ' is available, but the automatic update could not be installed: ' . $installError,
        'warning'
      );
      return;
    }

    ms_update_cache_write([
      'checked_at' => $now,
      'local_version' => $remoteVersion,
      'remote_version' => $remoteVersion,
      'status' => 'updated',
      'message' => ''
    ]);
    ms_update_set_notice(
      'updated-' . $remoteVersion,
      MS_APP_NAME . ' was automatically updated from version ' . MS_VERSION . ' to ' . $remoteVersion . '.',
      'success'
    );

    $location = (string)($_SERVER['REQUEST_URI'] ?? './');
    $location = str_replace(["\r", "\n"], '', $location);
    session_write_close();
    header('Location: ' . ($location !== '' ? $location : './'));
    exit;
  } finally {
    @flock($lock, LOCK_UN);
    fclose($lock);
  }
}

ms_auto_update();

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

function sql_exportable_statement(string $statement): bool {
  $clean = preg_replace('/\A(?:\s|--[^\r\n]*(?:\r\n|\r|\n|$)|\#[^\r\n]*(?:\r\n|\r|\n|$)|\/\*.*?\*\/)*/s', '', $statement);
  if (!is_string($clean)) {
    return false;
  }
  $clean = ltrim($clean);
  if (preg_match('/\A(?:SELECT|SHOW|DESCRIBE|DESC|EXPLAIN|TABLE|VALUES)\b/i', $clean) === 1) {
    return true;
  }
  return preg_match('/\AWITH\b/i', $clean) === 1
    && preg_match('/\bSELECT\b/i', $clean) === 1
    && preg_match('/\b(?:INSERT|UPDATE|DELETE|REPLACE|CALL|DO|LOAD)\b/i', $clean) !== 1;
}

function register_sql_result_export(string $statement): string {
  $exports = isset($_SESSION['ms_sql_exports']) && is_array($_SESSION['ms_sql_exports']) ? $_SESSION['ms_sql_exports'] : [];
  $cutoff = time() - 1800;
  foreach ($exports as $key => $entry) {
    if (!is_array($entry) || (int)($entry['created'] ?? 0) < $cutoff) {
      unset($exports[$key]);
    }
  }
  while (count($exports) >= 10) {
    array_shift($exports);
  }
  $token = bin2hex(random_bytes(24));
  $exports[$token] = ['database' => selected_db(), 'statement' => $statement, 'created' => time()];
  $_SESSION['ms_sql_exports'] = $exports;
  return $token;
}

function execute_sql(mysqli $db, string $sql, bool $showAll = false, int $displayLimit = MS_SQL_ROWS_DEFAULT): array {
  $started = microtime(true);
  $results = [];
  $displayLimit = max(1, min(100000, $displayLimit));
  $statements = split_sql_script($sql);
  if (!$statements) {
    throw new RuntimeException('No executable SQL statement found.');
  }
  foreach ($statements as $statement) {
    $exportable = sql_exportable_statement($statement);
    $exportToken = '';
    $result = $db->query($statement);
    if ($result === false) {
      throw new RuntimeException($db->error . ' — Statement: ' . substr($statement, 0, 300));
    }
    do {
    if ($result instanceof mysqli_result) {
      $fields = $result->fetch_fields();
      $totalRows = $result->num_rows;
      $rows = [];
      while ($row = $result->fetch_row()) {
        $rows[] = $row;
        if (!$showAll && count($rows) >= $displayLimit) {
          break;
        }
      }
      $resultToken = '';
      if ($exportable && $exportToken === '') {
        $exportToken = register_sql_result_export($statement);
        $resultToken = $exportToken;
      }
      $results[] = [
        'fields' => $fields,
        'rows' => $rows,
        'count' => $totalRows,
        'shown' => count($rows),
        'capped' => !$showAll && $totalRows > count($rows),
        'show_all' => $showAll,
        'display_limit' => $displayLimit,
        'export_token' => $resultToken,
        'affected' => null,
        'info' => ''
      ];
      $result->free();
    } else {
      $results[] = ['fields' => [], 'rows' => [], 'count' => null, 'shown' => 0, 'capped' => false, 'show_all' => false, 'display_limit' => $displayLimit, 'export_token' => '', 'affected' => $db->affected_rows, 'info' => $db->info];
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

function unique_result_names(array $names): array {
  $used = [];
  $unique = [];
  foreach ($names as $position => $name) {
    $base = trim((string)$name);
    if ($base === '') {
      $base = 'column_' . ($position + 1);
    }
    $candidate = $base;
    $suffix = 2;
    while (isset($used[strtolower($candidate)])) {
      $candidate = $base . '_' . $suffix;
      $suffix++;
    }
    $used[strtolower($candidate)] = true;
    $unique[] = $candidate;
  }
  return $unique;
}

function sql_result_export_entry(string $token): array {
  if (preg_match('/\A[a-f0-9]{48}\z/', $token) !== 1) {
    throw new RuntimeException('Invalid query-result export token.');
  }
  $exports = isset($_SESSION['ms_sql_exports']) && is_array($_SESSION['ms_sql_exports']) ? $_SESSION['ms_sql_exports'] : [];
  $entry = $exports[$token] ?? null;
  if (!is_array($entry) || (int)($entry['created'] ?? 0) < time() - 1800) {
    unset($exports[$token]);
    $_SESSION['ms_sql_exports'] = $exports;
    throw new RuntimeException('This query-result export has expired. Run the query again.');
  }
  $statement = (string)($entry['statement'] ?? '');
  $database = (string)($entry['database'] ?? '');
  if ($database === '' || !sql_exportable_statement($statement)) {
    throw new RuntimeException('This query result cannot be exported.');
  }
  return ['database' => $database, 'statement' => $statement, 'created' => (int)$entry['created']];
}

function stream_sql_result_export(mysqli $db, array $entry, string $format): void {
  if (!in_array($format, ['sql', 'csv', 'tsv'], true)) {
    throw new RuntimeException('Unsupported query-result export format.');
  }
  if (!$db->select_db((string)$entry['database'])) {
    throw new RuntimeException($db->error);
  }
  $result = $db->query((string)$entry['statement'], MYSQLI_USE_RESULT);
  if (!$result instanceof mysqli_result) {
    throw new RuntimeException($db->error ?: 'The statement did not return a result set.');
  }
  $fields = $result->fetch_fields();
  $displayNames = unique_result_names(array_map(static function ($field): string {
    return (string)$field->name;
  }, $fields));
  $stamp = gmdate('Ymd-His');

  if ($format === 'csv' || $format === 'tsv') {
    $delimiter = $format === 'tsv' ? "\t" : ',';
    $contentType = $format === 'tsv' ? 'text/tab-separated-values; charset=UTF-8' : 'text/csv; charset=UTF-8';
    download_headers('query-result-' . $stamp . '.' . $format, $contentType);
    $out = fopen('php://output', 'wb');
    if ($out === false) {
      $result->free();
      throw new RuntimeException('Cannot open the download stream.');
    }
    fwrite($out, "\xEF\xBB\xBF");
    fputcsv($out, $displayNames, $delimiter);
    while ($row = $result->fetch_row()) {
      fputcsv($out, $row, $delimiter);
    }
    $result->free();
    fclose($out);
    return;
  }

  $originTable = '';
  $originNames = [];
  $useOrigin = count($fields) > 0;
  foreach ($fields as $field) {
    $table = (string)$field->orgtable;
    $name = (string)$field->orgname;
    if ($table === '' || $name === '' || ($originTable !== '' && $originTable !== $table)) {
      $useOrigin = false;
    }
    if ($originTable === '') {
      $originTable = $table;
    }
    $originNames[] = $name;
  }
  if (count(array_unique(array_map('strtolower', $originNames))) !== count($originNames)) {
    $useOrigin = false;
  }
  $targetTable = $useOrigin ? $originTable : 'query_result';
  $columnNames = $useOrigin ? $originNames : $displayNames;
  $columns = array_map('qi', $columnNames);
  download_headers('query-result-' . $stamp . '.sql', 'application/sql; charset=UTF-8');
  echo "-- MySQL Studio query-result export\n";
  echo '-- Database: ' . str_replace(["\r", "\n"], ' ', (string)$entry['database']) . "\n";
  echo '-- Generated: ' . gmdate('Y-m-d H:i:s') . " UTC\n\n";
  echo "SET NAMES utf8mb4;\n\n";
  $batch = [];
  while ($row = $result->fetch_row()) {
    $values = [];
    foreach ($row as $value) {
      $values[] = $value === null ? 'NULL' : qs($db, $value);
    }
    $batch[] = '(' . implode(', ', $values) . ')';
    if (count($batch) >= 100) {
      echo 'INSERT INTO ' . qi($targetTable) . ' (' . implode(', ', $columns) . ") VALUES\n" . implode(",\n", $batch) . ";\n";
      $batch = [];
    }
  }
  if ($batch) {
    echo 'INSERT INTO ' . qi($targetTable) . ' (' . implode(', ', $columns) . ") VALUES\n" . implode(",\n", $batch) . ";\n";
  }
  $result->free();
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

function csv_export(mysqli $db, string $table, string $delimiter = ','): void {
  $result = $db->query('SELECT * FROM ' . qi($table), MYSQLI_USE_RESULT);
  if (!$result instanceof mysqli_result) {
    throw new RuntimeException($db->error);
  }
  $out = fopen('php://output', 'wb');
  $headers = [];
  foreach ($result->fetch_fields() as $field) {
    $headers[] = $field->name;
  }
  fputcsv($out, $headers, $delimiter);
  while ($row = $result->fetch_row()) {
    fputcsv($out, $row, $delimiter);
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

    if (g('download') === 'sql_result') {
      $entry = sql_result_export_entry(g('token'));
      session_write_close();
      stream_sql_result_export($db, $entry, g('format', 'csv'));
      exit;
    }

    if (g('download') === 'export') {
      $db->select_db(selected_db());
      $format = g('format', 'sql');
      $selected = isset($_GET['tables']) && is_array($_GET['tables']) ? array_map('strval', $_GET['tables']) : [];
      $available = array_column(db_all($db, 'SELECT TABLE_NAME FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE() ORDER BY TABLE_NAME'), 'TABLE_NAME');
      $tables = $selected ? array_values(array_intersect($available, $selected)) : $available;
      if ($format === 'csv' || $format === 'tsv') {
        if (count($tables) !== 1) {
          throw new RuntimeException(strtoupper($format) . ' export requires exactly one table.');
        }
        $contentType = $format === 'tsv' ? 'text/tab-separated-values; charset=UTF-8' : 'text/csv; charset=UTF-8';
        $delimiter = $format === 'tsv' ? "\t" : ',';
        download_headers($tables[0] . '.' . $format, $contentType);
        echo "\xEF\xBB\xBF";
        csv_export($db, $tables[0], $delimiter);
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
        $sqlDisplayLimit = max(1, min(100000, (int)p('row_limit', (string)browser_setting_int('mysqlStudioSqlRows', MS_SQL_ROWS_DEFAULT, 1, 100000))));
        [$sqlResults, $sqlTime] = execute_sql($db, $sql, p('show_all') === '1', $sqlDisplayLimit);
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
      } elseif ($action === 'clone_selected_prepare') {
        $table = g('table');
        if (!table_exists($db, $table)) {
          throw new RuntimeException('Table not found.');
        }
        $ids = isset($_POST['row_id']) && is_array($_POST['row_id']) ? array_map('strval', $_POST['row_id']) : [];
        $ids = array_values(array_unique($ids));
        $validIds = [];
        foreach ($ids as $encoded) {
          if (is_array(decode_identity($encoded))) {
            $validIds[] = $encoded;
          }
        }
        if (!$validIds) {
          throw new RuntimeException('Select at least one row to clone.');
        }
        $_SESSION['ms_clone_rows'] = [
          'database' => selected_db(),
          'table' => $table,
          'ids' => $validIds
        ];
        go(['page' => 'clone_rows'], count($validIds) . ' row(s) selected. Choose only the fields that must change.', 'info');
      } elseif ($action === 'clone_selected_cancel') {
        $selection = $_SESSION['ms_clone_rows'] ?? null;
        $table = is_array($selection) ? (string)($selection['table'] ?? g('table')) : g('table');
        unset($_SESSION['ms_clone_rows']);
        go(['page' => 'select', 'table' => $table], 'Cloning cancelled.', 'info');
      } elseif ($action === 'clone_selected_commit') {
        $selection = $_SESSION['ms_clone_rows'] ?? null;
        $table = g('table');
        if (!is_array($selection) || (string)($selection['database'] ?? '') !== selected_db() || (string)($selection['table'] ?? '') !== $table) {
          unset($_SESSION['ms_clone_rows']);
          throw new RuntimeException('The selected rows have expired or belong to another database or table. Select them again.');
        }
        $ids = isset($selection['ids']) && is_array($selection['ids']) ? array_values(array_unique(array_map('strval', $selection['ids']))) : [];
        if (!$ids || !table_exists($db, $table)) {
          throw new RuntimeException('No valid rows are available to clone.');
        }
        $columns = table_columns($db, $table);
        $changes = isset($_POST['clone_change']) && is_array($_POST['clone_change']) ? $_POST['clone_change'] : [];
        $values = isset($_POST['clone_value']) && is_array($_POST['clone_value']) ? $_POST['clone_value'] : [];
        $nulls = isset($_POST['clone_null']) && is_array($_POST['clone_null']) ? $_POST['clone_null'] : [];
        $expressions = isset($_POST['clone_expression']) && is_array($_POST['clone_expression']) ? $_POST['clone_expression'] : [];
        $targetColumns = [];
        $selectValues = [];
        foreach ($columns as $columnIndex => $column) {
          $name = (string)$column['COLUMN_NAME'];
          $extra = (string)$column['EXTRA'];
          if (strpos($extra, 'GENERATED') !== false || strpos($extra, 'auto_increment') !== false) {
            continue;
          }
          $targetColumns[] = qi($name);
          if (!isset($changes[$columnIndex])) {
            $selectValues[] = qi($name);
            continue;
          }
          $hasUpload = isset($_FILES['clone_upload']['tmp_name'][$columnIndex]) && (string)$_FILES['clone_upload']['tmp_name'][$columnIndex] !== '';
          if (isset($nulls[$columnIndex])) {
            $selectValues[] = 'NULL';
          } elseif ($hasUpload) {
            if ((int)$_FILES['clone_upload']['size'][$columnIndex] > 25 * 1024 * 1024) {
              throw new RuntimeException('Uploaded BLOB for ' . $name . ' is larger than 25 MB.');
            }
            $bytes = file_get_contents((string)$_FILES['clone_upload']['tmp_name'][$columnIndex]);
            $selectValues[] = qs($db, $bytes === false ? '' : $bytes);
          } elseif (!empty($expressions[$columnIndex])) {
            $expression = trim((string)($values[$columnIndex] ?? ''));
            if ($expression === '') {
              throw new RuntimeException('Enter an SQL expression for ' . $name . '.');
            }
            $selectValues[] = $expression;
          } else {
            $selectValues[] = qs($db, $values[$columnIndex] ?? '');
          }
        }
        $cloned = 0;
        $db->begin_transaction();
        try {
          foreach ($ids as $encoded) {
            $identity = decode_identity($encoded);
            if (!is_array($identity)) {
              throw new RuntimeException('A selected row identity is invalid.');
            }
            $where = row_identity_where($db, $columns, $identity);
            if ($targetColumns) {
              $sql = 'INSERT INTO ' . qi($table) . ' (' . implode(', ', $targetColumns) . ') SELECT ' . implode(', ', $selectValues) . ' FROM ' . qi($table) . ' WHERE ' . $where . ' LIMIT 1';
            } else {
              $source = db_one($db, 'SELECT 1 AS found FROM ' . qi($table) . ' WHERE ' . $where . ' LIMIT 1');
              if (!$source) {
                throw new RuntimeException('One of the selected rows no longer exists.');
              }
              $sql = 'INSERT INTO ' . qi($table) . ' () VALUES ()';
            }
            if (!$db->query($sql)) {
              throw new RuntimeException($db->error);
            }
            if ($db->affected_rows !== 1) {
              throw new RuntimeException('One of the selected rows no longer exists.');
            }
            $cloned++;
          }
          $db->commit();
        } catch (Throwable $cloneError) {
          $db->rollback();
          throw $cloneError;
        }
        unset($_SESSION['ms_clone_rows']);
        go(['page' => 'select', 'table' => $table], $cloned . ' row(s) cloned.');
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
<html lang="en" data-bs-theme="light" data-density="standard" data-scheme="ocean">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title><?= h($title) ?> · <?= h(MS_APP_NAME) ?></title>
  <script>
    (() => {
      'use strict';
      const menuKeys = ['databases','database','sql','export','schema','views','routines','triggers','events','processes','users','variables'];
      const defaultMenu = {};
      menuKeys.forEach(key => defaultMenu[key] = true);
      const defaults = {theme:'light',density:'standard',scheme:'ocean',sqlRows:1000,selectRows:50,truncateCells:false,menu:defaultMenu,tableLayouts:{}};
      const storageKey = 'mysqlStudioSettings.v1';
      window.msSettingsMeta = {menuKeys,defaults,storageKey};
      const boundedInteger = (value, fallback, minimum, maximum) => {
        const parsed = Number.parseInt(value, 10);
        return Number.isFinite(parsed) ? Math.max(minimum, Math.min(maximum, parsed)) : fallback;
      };
      window.msLoadSettings = () => {
        let stored = {};
        try { stored = JSON.parse(localStorage.getItem(storageKey) || '{}') || {}; } catch (error) { stored = {}; }
        const legacyTheme = localStorage.getItem('ms-theme');
        const theme = ['light','dark'].includes(stored.theme) ? stored.theme : (['light','dark'].includes(legacyTheme) ? legacyTheme : defaults.theme);
        const density = ['ultracompact','compact','standard','large'].includes(stored.density) ? stored.density : defaults.density;
        const schemes = ['ocean','indigo','emerald','teal','ruby','amber','violet','rose','slate','contrast'];
        const scheme = schemes.includes(stored.scheme) ? stored.scheme : defaults.scheme;
        const sqlRows = boundedInteger(stored.sqlRows, defaults.sqlRows, 1, 100000);
        const selectRows = boundedInteger(stored.selectRows, defaults.selectRows, 1, 500);
        const truncateCells = stored.truncateCells === true;
        const tableLayouts = stored.tableLayouts && typeof stored.tableLayouts === 'object' && !Array.isArray(stored.tableLayouts) ? stored.tableLayouts : {};
        const menu = {...defaultMenu};
        if (stored.menu && typeof stored.menu === 'object') menuKeys.forEach(key => menu[key] = stored.menu[key] !== false);
        return {theme,density,scheme,sqlRows,selectRows,truncateCells,menu,tableLayouts};
      };
      window.msSyncSettingsCookies = settings => {
        const secure = location.protocol === 'https:' ? '; Secure' : '';
        document.cookie = `mysqlStudioSqlRows=${settings.sqlRows}; Max-Age=31536000; Path=/; SameSite=Lax${secure}`;
        document.cookie = `mysqlStudioSelectRows=${settings.selectRows}; Max-Age=31536000; Path=/; SameSite=Lax${secure}`;
      };
      window.msSaveSettings = settings => {
        localStorage.setItem(storageKey, JSON.stringify(settings));
        localStorage.removeItem('ms-theme');
        window.msSyncSettingsCookies(settings);
      };
      window.msApplySettings = settings => {
        const root = document.documentElement;
        root.setAttribute('data-bs-theme', settings.theme);
        root.setAttribute('data-density', settings.density);
        root.setAttribute('data-scheme', settings.scheme);
        root.setAttribute('data-truncate-cells', settings.truncateCells ? 'true' : 'false');
        document.querySelectorAll('[data-ms-menu]').forEach(item => {
          item.hidden = settings.menu[item.dataset.msMenu] === false;
        });
        document.querySelectorAll('[data-ms-sql-row-limit]').forEach(input => input.value = settings.sqlRows);
        document.querySelectorAll('[data-ms-sql-limit-label]').forEach(label => label.textContent = settings.sqlRows.toLocaleString());
        document.querySelectorAll('[data-theme-toggle]').forEach(button => {
          const dark = settings.theme === 'dark';
          button.title = dark ? 'Switch to light mode' : 'Switch to dark mode';
          button.setAttribute('aria-label', button.title);
          const icon = button.querySelector('i');
          if (icon) icon.className = dark ? 'fa-solid fa-sun' : 'fa-solid fa-moon';
        });
      };
      const initialSettings = window.msLoadSettings();
      window.msSyncSettingsCookies(initialSettings);
      window.msApplySettings(initialSettings);
    })();
  </script>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.8/dist/css/bootstrap.min.css" rel="stylesheet">
  <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/7.0.1/css/all.min.css" rel="stylesheet">
  <style>
    :root{--sidebar:260px;--ms-accent:#0d6efd;--ms-accent-hover:#0b5ed7;--ms-accent-rgb:13,110,253;--ms-accent-text:#fff;--ms-link:#0a58ca}
    html[data-scheme="ocean"]{--ms-accent:#0d6efd;--ms-accent-hover:#0b5ed7;--ms-accent-rgb:13,110,253;--ms-accent-text:#fff;--ms-link:#0a58ca}
    html[data-scheme="indigo"]{--ms-accent:#6610f2;--ms-accent-hover:#520dc2;--ms-accent-rgb:102,16,242;--ms-accent-text:#fff;--ms-link:#5b0cd6}
    html[data-scheme="emerald"]{--ms-accent:#198754;--ms-accent-hover:#146c43;--ms-accent-rgb:25,135,84;--ms-accent-text:#fff;--ms-link:#157347}
    html[data-scheme="teal"]{--ms-accent:#0f766e;--ms-accent-hover:#115e59;--ms-accent-rgb:15,118,110;--ms-accent-text:#fff;--ms-link:#0f766e}
    html[data-scheme="ruby"]{--ms-accent:#c92a2a;--ms-accent-hover:#a61e1e;--ms-accent-rgb:201,42,42;--ms-accent-text:#fff;--ms-link:#b42323}
    html[data-scheme="amber"]{--ms-accent:#a65f00;--ms-accent-hover:#854d0e;--ms-accent-rgb:166,95,0;--ms-accent-text:#fff;--ms-link:#925400}
    html[data-scheme="violet"]{--ms-accent:#7c3aed;--ms-accent-hover:#6d28d9;--ms-accent-rgb:124,58,237;--ms-accent-text:#fff;--ms-link:#6d28d9}
    html[data-scheme="rose"]{--ms-accent:#be185d;--ms-accent-hover:#9d174d;--ms-accent-rgb:190,24,93;--ms-accent-text:#fff;--ms-link:#ad1457}
    html[data-scheme="slate"]{--ms-accent:#475569;--ms-accent-hover:#334155;--ms-accent-rgb:71,85,105;--ms-accent-text:#fff;--ms-link:#3f4c5f}
    html[data-scheme="contrast"]{--ms-accent:#111827;--ms-accent-hover:#000;--ms-accent-rgb:17,24,39;--ms-accent-text:#fff;--ms-link:#111827}
    html[data-bs-theme="dark"]{--ms-link:color-mix(in srgb,var(--ms-accent) 55%,white)}
    html[data-bs-theme="dark"][data-scheme="contrast"]{--ms-accent:#facc15;--ms-accent-hover:#eab308;--ms-accent-rgb:250,204,21;--ms-accent-text:#111;--ms-link:#fde047}
    body{min-height:100vh}.sidebar{width:var(--sidebar);position:fixed;inset:0 auto 0 0;overflow:auto;background:var(--bs-tertiary-bg);border-right:1px solid var(--bs-border-color)}.main{margin-left:var(--sidebar);padding:1.25rem}.brand{font-weight:700;letter-spacing:.02em}.table-scroll{overflow:auto;max-height:70vh}.table-scroll th{position:sticky;top:0;z-index:2;background:var(--bs-body-bg)}.ms-layout-table th[data-ms-column]{cursor:grab;user-select:none;padding-right:1rem}.ms-layout-table th[data-ms-column]:active{cursor:grabbing}.ms-layout-table th.ms-column-dragging{opacity:.45}.ms-layout-table th.ms-column-drop-before{box-shadow:inset 3px 0 0 var(--ms-accent)}.ms-layout-table th.ms-column-drop-after{box-shadow:inset -3px 0 0 var(--ms-accent)}.ms-col-resizer{position:absolute;top:0;right:-3px;bottom:0;width:8px;cursor:col-resize;z-index:4;touch-action:none}.ms-col-resizer::after{content:"";position:absolute;top:20%;bottom:20%;left:3px;border-left:1px solid var(--bs-border-color)}body.ms-column-resizing{cursor:col-resize!important;user-select:none!important}.cell-value{display:inline-block;max-width:420px;max-height:9rem;overflow:auto;white-space:pre-wrap}html[data-truncate-cells="true"] .ms-layout-table tbody td[data-ms-column]{max-width:320px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}html[data-truncate-cells="true"] .ms-layout-table tbody td[data-ms-column] .cell-value{display:block;max-width:100%;max-height:none;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}html[data-truncate-cells="true"] .ms-layout-table tbody td[data-ms-column] .cell-value br{display:none}.sql-editor{font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace;min-height:220px;tab-size:2}.code{font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace;white-space:pre-wrap}.schema-canvas{position:relative;min-height:650px;background-image:radial-gradient(var(--bs-border-color) 1px,transparent 1px);background-size:20px 20px}.schema-table{position:relative;display:inline-block;vertical-align:top;width:240px;margin:12px}.schema-line{color:var(--ms-accent)}.nav-link.active{font-weight:600}.danger-zone{border:1px solid var(--bs-danger-border-subtle);background:var(--bs-danger-bg-subtle)}
    a{color:var(--ms-link)}.text-primary{color:var(--ms-accent)!important}.bg-primary{background-color:var(--ms-accent)!important}.border-primary{border-color:var(--ms-accent)!important}.nav-pills{--bs-nav-pills-link-active-bg:var(--ms-accent)}.page-link{color:var(--ms-link)}.active>.page-link,.page-link.active{background-color:var(--ms-accent);border-color:var(--ms-accent);color:var(--ms-accent-text)}.form-check-input:checked{background-color:var(--ms-accent);border-color:var(--ms-accent)}.form-control:focus,.form-select:focus,.form-check-input:focus{border-color:rgba(var(--ms-accent-rgb),.65);box-shadow:0 0 0 .25rem rgba(var(--ms-accent-rgb),.2)}
    .btn-primary{--bs-btn-color:var(--ms-accent-text);--bs-btn-bg:var(--ms-accent);--bs-btn-border-color:var(--ms-accent);--bs-btn-hover-color:var(--ms-accent-text);--bs-btn-hover-bg:var(--ms-accent-hover);--bs-btn-hover-border-color:var(--ms-accent-hover);--bs-btn-active-color:var(--ms-accent-text);--bs-btn-active-bg:var(--ms-accent-hover);--bs-btn-active-border-color:var(--ms-accent-hover);--bs-btn-disabled-color:var(--ms-accent-text);--bs-btn-disabled-bg:var(--ms-accent);--bs-btn-disabled-border-color:var(--ms-accent)}
    html[data-density="ultracompact"]{--sidebar:220px;font-size:12px}html[data-density="ultracompact"] .main{padding:.45rem}html[data-density="ultracompact"] .sidebar{padding:.45rem!important}html[data-density="ultracompact"] .table>:not(caption)>*>*{padding:.12rem .3rem}html[data-density="ultracompact"] .form-control,html[data-density="ultracompact"] .form-select,html[data-density="ultracompact"] .btn{font-size:.75rem;padding:.16rem .38rem}html[data-density="ultracompact"] .card-body,html[data-density="ultracompact"] .card-header,html[data-density="ultracompact"] .card-footer{padding:.4rem .55rem}html[data-density="ultracompact"] .nav-link,html[data-density="ultracompact"] .list-group-item{padding:.2rem .35rem}html[data-density="ultracompact"] .mb-4{margin-bottom:.65rem!important}html[data-density="ultracompact"] .mb-3{margin-bottom:.45rem!important}html[data-density="ultracompact"] .g-3{--bs-gutter-x:.5rem;--bs-gutter-y:.5rem}
    html[data-density="compact"]{--sidebar:240px;font-size:14px}html[data-density="compact"] .main{padding:.8rem}html[data-density="compact"] .sidebar{padding:.75rem!important}html[data-density="compact"] .table>:not(caption)>*>*{padding:.28rem .45rem}html[data-density="compact"] .form-control,html[data-density="compact"] .form-select,html[data-density="compact"] .btn{font-size:.875rem;padding:.28rem .5rem}html[data-density="compact"] .card-body,html[data-density="compact"] .card-header,html[data-density="compact"] .card-footer{padding:.7rem .85rem}html[data-density="compact"] .nav-link,html[data-density="compact"] .list-group-item{padding:.35rem .55rem}
    html[data-density="large"]{--sidebar:295px;font-size:17px}html[data-density="large"] .main{padding:1.6rem}html[data-density="large"] .sidebar{padding:1.3rem!important}html[data-density="large"] .table>:not(caption)>*>*{padding:.75rem .85rem}html[data-density="large"] .form-control,html[data-density="large"] .form-select,html[data-density="large"] .btn{font-size:1rem;padding:.58rem .8rem}html[data-density="large"] .card-body,html[data-density="large"] .card-header,html[data-density="large"] .card-footer{padding:1.25rem}html[data-density="large"] .nav-link,html[data-density="large"] .list-group-item{padding:.7rem .85rem}
    .ms-page-loader{position:fixed;inset:0;z-index:20000;display:flex;align-items:center;justify-content:center;background:color-mix(in srgb,var(--bs-body-bg) 88%,transparent);backdrop-filter:blur(3px);-webkit-backdrop-filter:blur(3px)}.ms-page-loader[hidden]{display:none!important}.ms-page-loader-box{min-width:280px;max-width:90vw;padding:2rem 2.5rem;border:1px solid var(--bs-border-color);border-radius:1rem;background:var(--bs-body-bg);box-shadow:0 1.5rem 4rem rgba(0,0,0,.22);text-align:center}.ms-page-spinner{width:5rem;height:5rem;margin:0 auto 1.25rem;border:.5rem solid rgba(var(--ms-accent-rgb),.18);border-top-color:var(--ms-accent);border-radius:50%;animation:ms-page-spin .8s linear infinite}.ms-page-loader-text{font-size:1.6rem;font-weight:700;letter-spacing:.01em;color:var(--bs-body-color)}@keyframes ms-page-spin{to{transform:rotate(360deg)}}@media(prefers-reduced-motion:reduce){.ms-page-spinner{animation-duration:1.6s}}
    .ms-sql-editor-wrap{position:relative;border-radius:var(--bs-border-radius);background:var(--bs-body-bg)}.ms-sql-highlight{position:absolute;inset:0;z-index:1;margin:0;box-sizing:border-box;border-style:solid;border-color:transparent;overflow:hidden;pointer-events:none;white-space:pre-wrap;overflow-wrap:break-word;word-break:normal;color:var(--bs-body-color);background:var(--bs-body-bg);border-radius:inherit}.ms-smart-sql-input{position:relative;z-index:2;background:transparent!important;color:transparent!important;-webkit-text-fill-color:transparent!important;caret-color:var(--bs-body-color);resize:vertical}.ms-smart-sql-input::selection{background:rgba(var(--ms-accent-rgb),.28)}.ms-sql-highlight .sql-k{color:#7c3aed;font-weight:700}.ms-sql-highlight .sql-t{color:#0f766e;font-weight:600}.ms-sql-highlight .sql-f{color:#2563eb}.ms-sql-highlight .sql-s{color:#b45309}.ms-sql-highlight .sql-i{color:#be185d}.ms-sql-highlight .sql-c{color:#6b7280;font-style:italic}.ms-sql-highlight .sql-n{color:#0891b2}.ms-sql-highlight .sql-v{color:#9333ea}.ms-sql-highlight .sql-o{color:#dc2626}.ms-sql-autocomplete{position:absolute;z-index:1200;min-width:280px;max-width:min(460px,calc(100% - 8px));max-height:280px;overflow:auto;border:1px solid var(--bs-border-color);border-radius:.55rem;background:var(--bs-body-bg);box-shadow:0 .8rem 2.2rem rgba(0,0,0,.22);padding:.3rem}.ms-sql-autocomplete[hidden]{display:none!important}.ms-sql-suggestion{display:flex;align-items:center;gap:.6rem;width:100%;border:0;border-radius:.35rem;background:transparent;color:var(--bs-body-color);text-align:left;padding:.48rem .6rem}.ms-sql-suggestion:hover,.ms-sql-suggestion.active{background:rgba(var(--ms-accent-rgb),.12)}.ms-sql-suggestion-icon{width:1.35rem;text-align:center;color:var(--ms-accent)}.ms-sql-suggestion-main{min-width:0;flex:1}.ms-sql-suggestion-name{display:block;font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace;font-weight:650;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.ms-sql-suggestion-meta{display:block;font-size:.75em;color:var(--bs-secondary-color);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.ms-sql-autocomplete-title{padding:.25rem .55rem .35rem;color:var(--bs-secondary-color);font-size:.75em;text-transform:uppercase;letter-spacing:.06em;font-weight:700}html[data-bs-theme="dark"] .ms-sql-highlight .sql-k{color:#c4b5fd}html[data-bs-theme="dark"] .ms-sql-highlight .sql-t{color:#5eead4}html[data-bs-theme="dark"] .ms-sql-highlight .sql-f{color:#93c5fd}html[data-bs-theme="dark"] .ms-sql-highlight .sql-s{color:#fbbf24}html[data-bs-theme="dark"] .ms-sql-highlight .sql-i{color:#f9a8d4}html[data-bs-theme="dark"] .ms-sql-highlight .sql-c{color:#94a3b8}html[data-bs-theme="dark"] .ms-sql-highlight .sql-n{color:#67e8f9}html[data-bs-theme="dark"] .ms-sql-highlight .sql-v{color:#d8b4fe}html[data-bs-theme="dark"] .ms-sql-highlight .sql-o{color:#fca5a5}
    .settings-choice{cursor:pointer;border:2px solid var(--bs-border-color);transition:border-color .15s,transform .15s}.settings-choice:hover{border-color:rgba(var(--ms-accent-rgb),.55);transform:translateY(-1px)}.btn-check:checked+.settings-choice{border-color:var(--ms-accent);box-shadow:0 0 0 .2rem rgba(var(--ms-accent-rgb),.15)}.scheme-swatch{height:2rem;border-radius:.4rem;background:var(--swatch);box-shadow:inset 0 0 0 1px rgba(0,0,0,.1)}
    @media(max-width:991.98px){.sidebar{position:static;width:auto;height:auto}.main{margin-left:0}.sidebar .nav{flex-direction:row;overflow:auto;flex-wrap:nowrap}.sidebar .nav-link{white-space:nowrap}}@media print{.sidebar,.no-print{display:none!important}.main{margin:0;padding:0}.table-scroll{max-height:none;overflow:visible}}
  </style>
</head>
<body>
<div id="ms-page-loader" class="ms-page-loader" role="status" aria-live="polite" aria-label="Loading">
  <div class="ms-page-loader-box">
    <div class="ms-page-spinner" aria-hidden="true"></div>
    <div id="ms-page-loader-text" class="ms-page-loader-text">Loading...</div>
  </div>
</div>
<script>
(() => {
  'use strict';
  const loader = document.getElementById('ms-page-loader');
  const label = document.getElementById('ms-page-loader-text');
  window.msShowPageLoader = text => {
    if (!loader) return;
    if (label) label.textContent = text || 'Loading...';
    loader.hidden = false;
    loader.setAttribute('aria-label', text || 'Loading...');
  };
  window.msHidePageLoader = () => {
    if (loader) loader.hidden = true;
  };
  document.addEventListener('DOMContentLoaded', window.msHidePageLoader, {once:true});
  window.addEventListener('pageshow', () => {
    if (document.readyState !== 'loading') window.msHidePageLoader();
  });
})();
</script>
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
  document.addEventListener('click', event => {
    if (event.defaultPrevented || event.button !== 0 || event.ctrlKey || event.metaKey || event.shiftKey || event.altKey) return;
    const target = event.target instanceof Element ? event.target : null;
    const link = target ? target.closest('a[href]') : null;
    if (!link) return;

    const rawHref = (link.getAttribute('href') || '').trim();
    if (rawHref === '' || rawHref === '#' || rawHref.startsWith('javascript:')) return;
    if (link.hasAttribute('download') || link.hasAttribute('data-bs-toggle') || link.hasAttribute('data-bs-dismiss')) return;

    const linkTarget = (link.getAttribute('target') || '').toLowerCase();
    if (linkTarget !== '' && linkTarget !== '_self') return;

    let destination;
    try { destination = new URL(link.href, window.location.href); } catch (error) { return; }
    if (destination.protocol !== 'http:' && destination.protocol !== 'https:') return;
    if (destination.searchParams.has('download')) return;

    const current = new URL(window.location.href);
    const sameDocument = destination.origin === current.origin
      && destination.pathname === current.pathname
      && destination.search === current.search;
    if (sameDocument && (destination.hash !== '' || current.hash !== '')) return;

    if (typeof window.msShowPageLoader === 'function') window.msShowPageLoader('Changing page...');
  });
  const msSqlKeywords=new Set(`ACCESSIBLE ADD ALL ALTER ANALYZE AND AS ASC ASENSITIVE BEFORE BETWEEN BIGINT BINARY BLOB BOTH BY CALL CASCADE CASE CHANGE CHAR CHARACTER CHECK COLLATE COLUMN CONDITION CONNECTION CONSTRAINT CONTINUE CONVERT CREATE CROSS CUBE CUME_DIST CURRENT_DATE CURRENT_TIME CURRENT_TIMESTAMP CURRENT_USER CURSOR DATABASE DATABASES DAY_HOUR DAY_MICROSECOND DAY_MINUTE DAY_SECOND DEC DECIMAL DECLARE DEFAULT DELAYED DELETE DENSE_RANK DESC DESCRIBE DETERMINISTIC DISTINCT DISTINCTROW DIV DOUBLE DROP DUAL EACH ELSE ELSEIF EMPTY ENCLOSED ESCAPED EXISTS EXIT EXPLAIN FALSE FETCH FIRST_VALUE FLOAT FLOAT4 FLOAT8 FOR FORCE FOREIGN FROM FULLTEXT FUNCTION GENERATED GET GRANT GROUP GROUPING GROUPS HAVING HIGH_PRIORITY HOUR_MICROSECOND HOUR_MINUTE HOUR_SECOND IF IGNORE IN INDEX INFILE INNER INOUT INSENSITIVE INSERT INT INT1 INT2 INT3 INT4 INT8 INTEGER INTERVAL INTO IO_AFTER_GTIDS IO_BEFORE_GTIDS IS ITERATE JOIN JSON_TABLE KEY KEYS KILL LAG LAST_VALUE LEAD LEADING LEAVE LEFT LIKE LIMIT LINEAR LINES LOAD LOCALTIME LOCALTIMESTAMP LOCK LONG LONGBLOB LONGTEXT LOOP LOW_PRIORITY MASTER_BIND MASTER_SSL_VERIFY_SERVER_CERT MATCH MAXVALUE MEDIUMBLOB MEDIUMINT MEDIUMTEXT MIDDLEINT MINUTE_MICROSECOND MINUTE_SECOND MOD MODIFIES NATURAL NOT NO_WRITE_TO_BINLOG NTH_VALUE NTILE NULL NUMERIC OF ON OPTIMIZE OPTIMIZER_COSTS OPTION OPTIONALLY OR ORDER OUT OUTER OUTFILE OVER PARTITION PERCENT_RANK PRECISION PRIMARY PROCEDURE PURGE RANGE RANK READ READS READ_WRITE REAL RECURSIVE REFERENCES REGEXP RELEASE RENAME REPEAT REPLACE REQUIRE RESIGNAL RESTRICT RETURN REVOKE RIGHT RLIKE ROW ROWS ROW_NUMBER SCHEMA SCHEMAS SECOND_MICROSECOND SELECT SENSITIVE SEPARATOR SET SHOW SIGNAL SMALLINT SPATIAL SPECIFIC SQL SQLEXCEPTION SQLSTATE SQLWARNING SQL_BIG_RESULT SQL_CALC_FOUND_ROWS SQL_SMALL_RESULT SSL STARTING STORED STRAIGHT_JOIN SYSTEM TABLE TERMINATED THEN TINYBLOB TINYINT TINYTEXT TO TRAILING TRIGGER TRUE UNDO UNION UNIQUE UNLOCK UNSIGNED UPDATE USAGE USE USING UTC_DATE UTC_TIME UTC_TIMESTAMP VALUES VARBINARY VARCHAR VARCHARACTER VARYING VIRTUAL WHEN WHERE WHILE WINDOW WITH WRITE XOR YEAR_MONTH ZEROFILL`.split(/\s+/));
  const msSqlTypes=new Set(`BIT BOOL BOOLEAN CHAR VARCHAR BINARY VARBINARY TINYTEXT TEXT MEDIUMTEXT LONGTEXT TINYBLOB BLOB MEDIUMBLOB LONGBLOB ENUM SET JSON DATE DATETIME TIMESTAMP TIME YEAR TINYINT SMALLINT MEDIUMINT INT INTEGER BIGINT DECIMAL DEC NUMERIC FIXED FLOAT DOUBLE REAL GEOMETRY POINT LINESTRING POLYGON MULTIPOINT MULTILINESTRING MULTIPOLYGON GEOMETRYCOLLECTION VECTOR UUID INET6`.split(/\s+/));
  const msSqlFunctions=new Set(`ABS ACOS ADDDATE ADDTIME AES_DECRYPT AES_ENCRYPT ANY_VALUE ASCII ASIN ATAN ATAN2 AVG BENCHMARK BIN BIT_COUNT BIT_LENGTH CEIL CEILING CHAR_LENGTH CHARACTER_LENGTH COALESCE CONCAT CONCAT_WS CONV CONVERT_TZ COS COT COUNT CRC32 CURDATE CURRENT_DATE CURRENT_TIME CURRENT_TIMESTAMP CURTIME DATABASE DATE DATE_ADD DATE_FORMAT DATE_SUB DATEDIFF DAY DAYNAME DAYOFMONTH DAYOFWEEK DAYOFYEAR DEGREES ELT EXP EXPORT_SET EXTRACT FIELD FIND_IN_SET FLOOR FORMAT FOUND_ROWS FROM_DAYS FROM_UNIXTIME GET_FORMAT GREATEST GROUP_CONCAT HEX HOUR IFNULL INET_ATON INET_NTOA INSERT INSTR INTERVAL ISNULL JSON_ARRAY JSON_ARRAYAGG JSON_CONTAINS JSON_EXTRACT JSON_OBJECT JSON_OBJECTAGG JSON_PRETTY JSON_QUOTE JSON_SEARCH JSON_SET LCASE LEAST LEFT LENGTH LN LOAD_FILE LOCATE LOG LOG10 LOG2 LOWER LPAD LTRIM MAKEDATE MAKETIME MAX MD5 MICROSECOND MID MIN MINUTE MOD MONTH MONTHNAME NOW NULLIF OCT OCTET_LENGTH ORD PERIOD_ADD PERIOD_DIFF PI POSITION POW POWER QUARTER RADIANS RAND REPEAT REPLACE REVERSE RIGHT ROUND RPAD RTRIM SEC_TO_TIME SECOND SHA SHA1 SHA2 SIGN SIN SPACE SQRT STD STDDEV STDDEV_POP STDDEV_SAMP STRCMP SUBDATE SUBSTR SUBSTRING SUBSTRING_INDEX SUM SYSDATE TAN TIME TIME_FORMAT TIME_TO_SEC TIMEDIFF TIMESTAMP TIMESTAMPADD TIMESTAMPDIFF TO_DAYS TRIM TRUNCATE UCASE UNHEX UNIX_TIMESTAMP UPPER UTC_DATE UTC_TIME UTC_TIMESTAMP UUID WEEK WEEKDAY WEEKOFYEAR YEAR`.split(/\s+/));
  const msHtmlEscape=value=>value.replace(/[&<>]/g,char=>char==='&'?'&amp;':char==='<'?'&lt;':'&gt;');
  const msSqlSpan=(cls,value)=>`<span class="${cls}">${msHtmlEscape(value)}</span>`;
  const msHighlightSql=sql=>{
    let out='',i=0;
    const length=sql.length;
    while(i<length){
      const ch=sql[i],next=i+1<length?sql[i+1]:'';
      if(ch==='-'&&next==='-'&&(i+2>=length||/\s/.test(sql[i+2]))){let j=i+2;while(j<length&&sql[j]!=='\n')j++;out+=msSqlSpan('sql-c',sql.slice(i,j));i=j;continue;}
      if(ch==='#'){let j=i+1;while(j<length&&sql[j]!=='\n')j++;out+=msSqlSpan('sql-c',sql.slice(i,j));i=j;continue;}
      if(ch==='/'&&next==='*'){let j=i+2;while(j<length&&!(sql[j]==='*'&&sql[j+1]==='/'))j++;j=Math.min(length,j+2);out+=msSqlSpan('sql-c',sql.slice(i,j));i=j;continue;}
      if(ch==="'"||ch==='"'||ch==='`'){
        const quote=ch;let j=i+1;
        while(j<length){
          if(sql[j]==='\\'&&j+1<length){j+=2;continue;}
          if(sql[j]===quote){if(j+1<length&&sql[j+1]===quote){j+=2;continue;}j++;break;}
          j++;
        }
        out+=msSqlSpan(quote==='`'?'sql-i':'sql-s',sql.slice(i,j));i=j;continue;
      }
      if(ch==='@'){let j=i+1;while(j<length&&/[A-Za-z0-9_@$]/.test(sql[j]))j++;out+=msSqlSpan('sql-v',sql.slice(i,j));i=j;continue;}
      if(/[0-9]/.test(ch)&&(i===0||!/[A-Za-z0-9_$]/.test(sql[i-1]))){let j=i+1;while(j<length&&/[0-9A-Fa-fxXbB.eE+-]/.test(sql[j]))j++;out+=msSqlSpan('sql-n',sql.slice(i,j));i=j;continue;}
      if(/[A-Za-z_$]/.test(ch)){
        let j=i+1;while(j<length&&/[A-Za-z0-9_$]/.test(sql[j]))j++;
        const word=sql.slice(i,j),upper=word.toUpperCase();let k=j;while(k<length&&/\s/.test(sql[k]))k++;
        if(msSqlKeywords.has(upper))out+=msSqlSpan('sql-k',word);
        else if(msSqlTypes.has(upper))out+=msSqlSpan('sql-t',word);
        else if(msSqlFunctions.has(upper)||sql[k]==='(')out+=msSqlSpan('sql-f',word);
        else out+=msHtmlEscape(word);
        i=j;continue;
      }
      if(/[=<>!+*/%|&^-]/.test(ch)){let j=i+1;while(j<length&&/[=<>!+*/%|&^-]/.test(sql[j]))j++;out+=msSqlSpan('sql-o',sql.slice(i,j));i=j;continue;}
      out+=msHtmlEscape(ch);i++;
    }
    return out;
  };
  const msSqlQuoteIdentifier=name=>/^[A-Za-z_$][A-Za-z0-9_$]*$/.test(name)&&!msSqlKeywords.has(name.toUpperCase())?name:'`'+name.replace(/`/g,'``')+'`';
  const msSqlCaretPosition=(textarea,position)=>{
    const style=getComputedStyle(textarea),mirror=document.createElement('div');
    ['boxSizing','width','borderTopWidth','borderRightWidth','borderBottomWidth','borderLeftWidth','paddingTop','paddingRight','paddingBottom','paddingLeft','fontStyle','fontVariant','fontWeight','fontStretch','fontSize','fontFamily','lineHeight','letterSpacing','textTransform','textAlign','textIndent','wordSpacing','tabSize'].forEach(prop=>mirror.style[prop]=style[prop]);
    mirror.style.position='absolute';mirror.style.visibility='hidden';mirror.style.left='-10000px';mirror.style.top='0';mirror.style.whiteSpace='pre-wrap';mirror.style.overflowWrap='break-word';mirror.style.wordBreak='normal';
    mirror.textContent=textarea.value.slice(0,position);
    const marker=document.createElement('span');marker.textContent=textarea.value.slice(position,position+1)||'.';mirror.appendChild(marker);document.body.appendChild(mirror);
    const result={left:marker.offsetLeft-textarea.scrollLeft,top:marker.offsetTop-textarea.scrollTop,height:Number.parseFloat(style.lineHeight)||Number.parseFloat(style.fontSize)*1.5||20};mirror.remove();return result;
  };
  const msInitSqlEditor=textarea=>{
    const wrap=document.createElement('div');wrap.className='ms-sql-editor-wrap';textarea.parentNode.insertBefore(wrap,textarea);wrap.appendChild(textarea);textarea.classList.add('ms-smart-sql-input');
    const highlight=document.createElement('pre');highlight.className='ms-sql-highlight';highlight.setAttribute('aria-hidden','true');wrap.insertBefore(highlight,textarea);
    const popup=document.createElement('div');popup.className='ms-sql-autocomplete';popup.hidden=true;popup.setAttribute('role','listbox');wrap.appendChild(popup);
    const copyGeometry=()=>{const style=getComputedStyle(textarea);['paddingTop','paddingRight','paddingBottom','paddingLeft','fontFamily','fontSize','fontWeight','fontStyle','lineHeight','letterSpacing','borderTopWidth','borderRightWidth','borderBottomWidth','borderLeftWidth'].forEach(prop=>highlight.style[prop]=style[prop]);};
    const syncHighlight=()=>{highlight.innerHTML=msHighlightSql(textarea.value)+'\n';highlight.scrollTop=textarea.scrollTop;highlight.scrollLeft=textarea.scrollLeft;};
    copyGeometry();syncHighlight();
    let schema=null,context=null,suggestions=[],activeIndex=0;
    if(textarea.dataset.msSqlSchemaId){const node=document.getElementById(textarea.dataset.msSqlSchemaId);if(node){try{schema=JSON.parse(node.textContent||'{}');}catch(error){schema=null;}}}
    const tableNames=schema&&Array.isArray(schema.tables)?schema.tables:[];
    const columnMap=schema&&schema.columns&&typeof schema.columns==='object'?schema.columns:{};
    const tableLookup=new Map(tableNames.map(item=>[String(item.name||'').toLowerCase(),item]));
    const closePopup=()=>{popup.hidden=true;popup.innerHTML='';context=null;suggestions=[];activeIndex=0;};
    const rankItems=(items,prefix)=>{const needle=prefix.toLowerCase();return items.filter(item=>String(item.name||'').toLowerCase().includes(needle)).sort((a,b)=>{const an=String(a.name||'').toLowerCase(),bn=String(b.name||'').toLowerCase(),as=an.startsWith(needle)?0:1,bs=bn.startsWith(needle)?0:1;return as-bs||an.localeCompare(bn);}).slice(0,24);};
    const resolveTable=name=>{const exact=tableLookup.get(String(name||'').toLowerCase());return exact?String(exact.name):'';};
    const detectContext=()=>{
      if(!schema||document.activeElement!==textarea)return null;
      const cursor=textarea.selectionStart,before=textarea.value.slice(0,cursor);
      const fieldMatch=before.match(/(?:`([^`\r\n]+)`|([A-Za-z0-9_$]+))\.(\`?)([A-Za-z0-9_$]*)$/);
      if(fieldMatch){const table=resolveTable(fieldMatch[1]||fieldMatch[2]);if(table)return{kind:'column',table,prefix:fieldMatch[4]||'',start:cursor-(fieldMatch[3]||'').length-(fieldMatch[4]||'').length,end:cursor};}
      const tail=(before.split(';').pop()||'');
      let match=tail.match(/\b(?:UPDATE|FROM|JOIN|INTO|DESCRIBE|DESC)\s+(\`?)([A-Za-z0-9_$]*)$/i);
      if(match)return{kind:'table',prefix:match[2]||'',start:cursor-(match[1]||'').length-(match[2]||'').length,end:cursor,insertMode:'plain'};
      match=tail.match(/\b(?:ALTER|TRUNCATE)\s+TABLE\s+(\`?)([A-Za-z0-9_$]*)$/i);
      if(match)return{kind:'table',prefix:match[2]||'',start:cursor-(match[1]||'').length-(match[2]||'').length,end:cursor,insertMode:'plain'};
      match=tail.match(/\b(?:DELETE\s+FROM|REPLACE\s+INTO|INSERT\s+INTO)\s+(\`?)([A-Za-z0-9_$]*)$/i);
      if(match)return{kind:'table',prefix:match[2]||'',start:cursor-(match[1]||'').length-(match[2]||'').length,end:cursor,insertMode:'plain'};
      match=tail.match(/\bINSERT\s+(\`?)([A-Za-z0-9_$]*)$/i);
      if(match)return{kind:'table',prefix:match[2]||'',start:cursor-(match[1]||'').length-(match[2]||'').length,end:cursor,insertMode:'insert'};
      match=tail.match(/\bSELECT\s+(\`?)([A-Za-z0-9_$]*)$/i);
      if(match)return{kind:'table',prefix:match[2]||'',start:cursor-(match[1]||'').length-(match[2]||'').length,end:cursor,insertMode:'select'};
      return null;
    };
    const applySuggestion=index=>{
      const item=suggestions[index];if(!item||!context)return;
      let replacement=msSqlQuoteIdentifier(String(item.name));
      if(context.kind==='table'&&context.insertMode==='select')replacement='* FROM '+replacement;
      else if(context.kind==='table'&&context.insertMode==='insert')replacement='INTO '+replacement;
      textarea.setRangeText(replacement,context.start,context.end,'end');textarea.dispatchEvent(new Event('input',{bubbles:true}));closePopup();textarea.focus();
    };
    const renderPopup=()=>{
      context=detectContext();if(!context){closePopup();return;}
      if(context.kind==='column')suggestions=rankItems(Array.isArray(columnMap[context.table])?columnMap[context.table]:[],context.prefix);
      else suggestions=rankItems(tableNames,context.prefix);
      if(!suggestions.length){closePopup();return;}
      activeIndex=0;popup.innerHTML='';
      const title=document.createElement('div');title.className='ms-sql-autocomplete-title';title.textContent=context.kind==='column'?'Columns · '+context.table:'Tables';popup.appendChild(title);
      suggestions.forEach((item,index)=>{const button=document.createElement('button');button.type='button';button.className='ms-sql-suggestion'+(index===activeIndex?' active':'');button.setAttribute('role','option');button.innerHTML=`<span class="ms-sql-suggestion-icon"><i class="fa-solid ${context.kind==='column'?'fa-table-columns':'fa-table'}"></i></span><span class="ms-sql-suggestion-main"><span class="ms-sql-suggestion-name"></span><span class="ms-sql-suggestion-meta"></span></span>`;button.querySelector('.ms-sql-suggestion-name').textContent=String(item.name||'');button.querySelector('.ms-sql-suggestion-meta').textContent=context.kind==='column'?String(item.type||'')+(item.key?' · '+item.key:''):String(item.type||'TABLE');button.addEventListener('mousedown',event=>event.preventDefault());button.addEventListener('click',()=>applySuggestion(index));popup.appendChild(button);});
      const caret=msSqlCaretPosition(textarea,textarea.selectionStart),popupWidth=Math.min(460,Math.max(280,textarea.clientWidth-8));popup.style.maxWidth=popupWidth+'px';popup.style.left=Math.max(4,Math.min(caret.left,Math.max(4,textarea.clientWidth-popupWidth)))+'px';popup.style.top=Math.max(4,caret.top+caret.height+2)+'px';popup.hidden=false;
    };
    const updateActive=delta=>{if(!suggestions.length)return;activeIndex=(activeIndex+delta+suggestions.length)%suggestions.length;popup.querySelectorAll('.ms-sql-suggestion').forEach((item,index)=>item.classList.toggle('active',index===activeIndex));const active=popup.querySelectorAll('.ms-sql-suggestion')[activeIndex];if(active)active.scrollIntoView({block:'nearest'});};
    textarea.addEventListener('input',()=>{syncHighlight();renderPopup();});
    textarea.addEventListener('scroll',()=>{syncHighlight();if(!popup.hidden)renderPopup();});
    textarea.addEventListener('click',renderPopup);
    textarea.addEventListener('keyup',event=>{if(['ArrowLeft','ArrowRight','Home','End','PageUp','PageDown'].includes(event.key))renderPopup();});
    textarea.addEventListener('keydown',event=>{
      if((event.ctrlKey||event.metaKey)&&event.key==='Enter'){event.preventDefault();if(textarea.form)textarea.form.requestSubmit();return;}
      if((event.ctrlKey||event.metaKey)&&event.key===' '){event.preventDefault();renderPopup();return;}
      if(!popup.hidden&&suggestions.length){if(event.key==='ArrowDown'){event.preventDefault();updateActive(1);return;}if(event.key==='ArrowUp'){event.preventDefault();updateActive(-1);return;}if(event.key==='Enter'||event.key==='Tab'){event.preventDefault();applySuggestion(activeIndex);return;}if(event.key==='Escape'){event.preventDefault();closePopup();return;}}
      if(event.key==='Tab'){event.preventDefault();const start=textarea.selectionStart,end=textarea.selectionEnd;textarea.setRangeText('  ',start,end,'end');textarea.dispatchEvent(new Event('input',{bubbles:true}));}
    });
    textarea.addEventListener('blur',()=>setTimeout(()=>{if(!wrap.contains(document.activeElement))closePopup();},120));
    if(window.ResizeObserver)new ResizeObserver(()=>{copyGeometry();syncHighlight();}).observe(textarea);
  };
  document.querySelectorAll('textarea.sql-editor').forEach(msInitSqlEditor);
  document.querySelectorAll('[data-check-all]').forEach(el => el.addEventListener('change', () => {
    document.querySelectorAll(el.dataset.checkAll).forEach(box => box.checked=el.checked);
  }));
  let settings=window.msLoadSettings();
  window.msApplySettings(settings);
  document.querySelectorAll('[data-theme-toggle]').forEach(el => el.addEventListener('click', () => {
    settings.theme=settings.theme==='dark'?'light':'dark';
    window.msSaveSettings(settings);
    window.msApplySettings(settings);
    if(settingsForm){const input=settingsForm.querySelector(`[name="theme"][value="${settings.theme}"]`);if(input)input.checked=true;}
  }));
  const settingsForm=document.getElementById('ms-settings-form');
  if(settingsForm){
    const selectCurrent=()=>{
      const theme=settingsForm.querySelector(`[name="theme"][value="${settings.theme}"]`);
      const density=settingsForm.querySelector(`[name="density"][value="${settings.density}"]`);
      const scheme=settingsForm.querySelector(`[name="scheme"][value="${settings.scheme}"]`);
      if(theme)theme.checked=true;if(density)density.checked=true;if(scheme)scheme.checked=true;
      settingsForm.elements.sqlRows.value=settings.sqlRows;
      settingsForm.elements.selectRows.value=settings.selectRows;
      settingsForm.elements.truncateCells.checked=settings.truncateCells;
      window.msSettingsMeta.menuKeys.forEach(key=>{const input=settingsForm.querySelector(`[name="menu[${key}]"]`);if(input)input.checked=settings.menu[key]!==false;});
    };
    selectCurrent();
    settingsForm.addEventListener('change',()=>{
      const preview={theme:settingsForm.elements.theme.value,density:settingsForm.elements.density.value,scheme:settingsForm.elements.scheme.value,sqlRows:Math.max(1,Math.min(100000,Number.parseInt(settingsForm.elements.sqlRows.value,10)||window.msSettingsMeta.defaults.sqlRows)),selectRows:Math.max(1,Math.min(500,Number.parseInt(settingsForm.elements.selectRows.value,10)||window.msSettingsMeta.defaults.selectRows)),truncateCells:settingsForm.elements.truncateCells.checked,menu:{},tableLayouts:settings.tableLayouts||{}};
      window.msSettingsMeta.menuKeys.forEach(key=>preview.menu[key]=settingsForm.querySelector(`[name="menu[${key}]"]`).checked);
      window.msApplySettings(preview);
    });
    settingsForm.addEventListener('submit',event=>{
      event.preventDefault();
      settings={theme:settingsForm.elements.theme.value,density:settingsForm.elements.density.value,scheme:settingsForm.elements.scheme.value,sqlRows:Math.max(1,Math.min(100000,Number.parseInt(settingsForm.elements.sqlRows.value,10)||window.msSettingsMeta.defaults.sqlRows)),selectRows:Math.max(1,Math.min(500,Number.parseInt(settingsForm.elements.selectRows.value,10)||window.msSettingsMeta.defaults.selectRows)),truncateCells:settingsForm.elements.truncateCells.checked,menu:{},tableLayouts:settings.tableLayouts||{}};
      window.msSettingsMeta.menuKeys.forEach(key=>settings.menu[key]=settingsForm.querySelector(`[name="menu[${key}]"]`).checked);
      window.msSaveSettings(settings);window.msApplySettings(settings);
      const saved=document.getElementById('ms-settings-saved');saved.classList.remove('d-none');setTimeout(()=>saved.classList.add('d-none'),2500);
    });
    document.getElementById('ms-menu-show-all').addEventListener('click',()=>{window.msSettingsMeta.menuKeys.forEach(key=>settingsForm.querySelector(`[name="menu[${key}]"]`).checked=true);settingsForm.dispatchEvent(new Event('change'));});
    document.getElementById('ms-menu-hide-all').addEventListener('click',()=>{window.msSettingsMeta.menuKeys.forEach(key=>settingsForm.querySelector(`[name="menu[${key}]"]`).checked=false);settingsForm.dispatchEvent(new Event('change'));});
    document.getElementById('ms-settings-reset').addEventListener('click',()=>{settings=JSON.parse(JSON.stringify(window.msSettingsMeta.defaults));selectCurrent();window.msSaveSettings(settings);window.msApplySettings(settings);const saved=document.getElementById('ms-settings-saved');saved.classList.remove('d-none');setTimeout(()=>saved.classList.add('d-none'),2500);});
  }
  const arraysEqual=(left,right)=>Array.isArray(left)&&Array.isArray(right)&&left.length===right.length&&left.every((value,index)=>value===right[index]);
  document.querySelectorAll('[data-ms-table-layout]').forEach(table=>{
    let nativeColumns=[];
    try{nativeColumns=JSON.parse(table.dataset.msColumns||'[]');}catch(error){nativeColumns=[];}
    if(!Array.isArray(nativeColumns)||!nativeColumns.length||nativeColumns.some(column=>typeof column!=='string'))return;
    const layoutKey=table.dataset.msLayoutKey||'';
    const context={server:table.dataset.msServer||'',database:table.dataset.msDatabase||'',table:table.dataset.msTable||''};
    if(!layoutKey||!context.server||!context.database||!context.table)return;
    if(!settings.tableLayouts||typeof settings.tableLayouts!=='object'||Array.isArray(settings.tableLayouts))settings.tableLayouts={};
    let layout=settings.tableLayouts[layoutKey]||null;
    const widthsAreValid=layout&&layout.widths&&typeof layout.widths==='object'&&!Array.isArray(layout.widths)&&Object.entries(layout.widths).every(([column,width])=>nativeColumns.includes(column)&&Number.isFinite(Number(width))&&Number(width)>=48&&Number(width)<=1200);
    const layoutIsValid=layout&&layout.server===context.server&&layout.database===context.database&&layout.table===context.table&&arraysEqual(layout.columns,nativeColumns)&&Array.isArray(layout.order)&&layout.order.length===nativeColumns.length&&new Set(layout.order).size===nativeColumns.length&&layout.order.every(column=>nativeColumns.includes(column))&&widthsAreValid;
    if(layout&&!layoutIsValid){delete settings.tableLayouts[layoutKey];window.msSaveSettings(settings);layout=null;}
    const cellsFor=column=>Array.from(table.querySelectorAll('[data-ms-column]')).filter(cell=>cell.dataset.msColumn===column);
    const setColumnWidth=(column,width)=>{
      const pixels=Math.max(48,Math.min(1200,Math.round(width)));
      cellsFor(column).forEach(cell=>{cell.style.width=`${pixels}px`;cell.style.minWidth=`${pixels}px`;cell.style.maxWidth=`${pixels}px`;});
      return pixels;
    };
    const applyOrder=order=>{
      table.querySelectorAll('tr').forEach(row=>{
        const cells=new Map(Array.from(row.children).filter(cell=>cell.dataset&&cell.dataset.msColumn).map(cell=>[cell.dataset.msColumn,cell]));
        order.forEach(column=>{const cell=cells.get(column);if(cell)row.appendChild(cell);});
      });
    };
    if(layout){applyOrder(layout.order);Object.entries(layout.widths).forEach(([column,width])=>setColumnWidth(column,Number(width)));}
    const saveLayout=()=>{
      const order=Array.from(table.querySelectorAll('thead th[data-ms-column]')).map(th=>th.dataset.msColumn);
      const widths={};
      table.querySelectorAll('thead th[data-ms-column]').forEach(th=>{const width=Number.parseInt(th.style.width,10);if(Number.isFinite(width))widths[th.dataset.msColumn]=width;});
      settings.tableLayouts[layoutKey]={server:context.server,database:context.database,table:context.table,columns:[...nativeColumns],order,widths};
      window.msSaveSettings(settings);
    };
    const clearDropMarkers=()=>table.querySelectorAll('.ms-column-drop-before,.ms-column-drop-after').forEach(th=>th.classList.remove('ms-column-drop-before','ms-column-drop-after'));
    let draggedColumn='';
    table.querySelectorAll('thead th[data-ms-column]').forEach(th=>{
      th.addEventListener('dragstart',event=>{
        if(event.target instanceof Element&&event.target.closest('[data-ms-col-resizer]')){event.preventDefault();return;}
        draggedColumn=th.dataset.msColumn;th.classList.add('ms-column-dragging');event.dataTransfer.effectAllowed='move';event.dataTransfer.setData('text/plain',draggedColumn);
      });
      th.addEventListener('dragover',event=>{
        if(!draggedColumn||draggedColumn===th.dataset.msColumn)return;
        event.preventDefault();event.dataTransfer.dropEffect='move';clearDropMarkers();
        const rect=th.getBoundingClientRect();th.classList.add(event.clientX<rect.left+rect.width/2?'ms-column-drop-before':'ms-column-drop-after');
      });
      th.addEventListener('drop',event=>{
        if(!draggedColumn||draggedColumn===th.dataset.msColumn)return;
        event.preventDefault();
        const before=th.classList.contains('ms-column-drop-before');
        table.querySelectorAll('tr').forEach(row=>{
          const source=Array.from(row.children).find(cell=>cell.dataset&&cell.dataset.msColumn===draggedColumn);
          const target=Array.from(row.children).find(cell=>cell.dataset&&cell.dataset.msColumn===th.dataset.msColumn);
          if(source&&target)row.insertBefore(source,before?target:target.nextSibling);
        });
        clearDropMarkers();saveLayout();
      });
      th.addEventListener('dragend',()=>{draggedColumn='';th.classList.remove('ms-column-dragging');clearDropMarkers();});
      const handle=th.querySelector('[data-ms-col-resizer]');
      if(handle)handle.addEventListener('pointerdown',event=>{
        if(event.button!==0)return;
        event.preventDefault();event.stopPropagation();th.draggable=false;document.body.classList.add('ms-column-resizing');
        const startX=event.clientX,startWidth=th.getBoundingClientRect().width,column=th.dataset.msColumn;
        let finished=false;
        const move=moveEvent=>setColumnWidth(column,startWidth+moveEvent.clientX-startX);
        const finish=()=>{if(finished)return;finished=true;window.removeEventListener('pointermove',move);window.removeEventListener('pointerup',finish);window.removeEventListener('pointercancel',finish);document.body.classList.remove('ms-column-resizing');th.draggable=true;saveLayout();};
        window.addEventListener('pointermove',move);window.addEventListener('pointerup',finish);window.addEventListener('pointercancel',finish);
      });
    });
  });
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
      <a class="brand text-decoration-none d-flex align-items-center gap-2" href="?page=databases"><span><i class="fa-solid fa-cube me-2"></i><?= h(MS_APP_NAME) ?></span><span class="badge text-bg-secondary fw-normal">v<?= h(MS_VERSION) ?></span></a>
      <button class="btn btn-sm btn-secondary" type="button" data-theme-toggle title="Switch to dark mode" aria-label="Switch to dark mode"><i class="fa-solid fa-moon"></i></button>
    </div>
    <?php if ($dbName !== '') { ?><div class="small text-body-secondary mb-2 text-truncate" title="<?= h($dbName) ?>">Database: <strong><?= h($dbName) ?></strong></div><?php } ?>
    <nav class="nav nav-pills flex-column gap-1">
      <?php foreach ($items as [$key, $icon, $label]) { if ($dbName === '' && !in_array($key, ['databases', 'processes', 'users', 'variables'], true)) continue; ?>
        <a class="nav-link <?= $page === $key ? 'active' : 'text-body' ?>" data-ms-menu="<?= h($key) ?>" href="?page=<?= h($key) ?>"><i class="fa-solid <?= h($icon) ?> fa-fw me-2"></i><?= h($label) ?></a>
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
    <hr><a class="nav-link mb-2 <?= $page === 'settings' ? 'active' : 'text-body' ?>" href="?page=settings"><i class="fa-solid fa-gear fa-fw me-2"></i>Settings</a>
    <form method="post"><input type="hidden" name="action" value="logout"><?= csrf_field() ?><button class="btn btn-secondary btn-sm w-100"><i class="fa-solid fa-right-from-bracket me-1"></i>Log out</button></form>
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
      ?><div class="table-responsive"><table class="table table-sm table-striped mb-0"><thead><tr><?php foreach ($result['fields'] as $field) { ?><th><?= h($field->name) ?></th><?php } ?></tr></thead><tbody><?php foreach ($result['rows'] as $row) { ?><tr><?php foreach ($row as $value) { ?><td><?= render_value($value) ?></td><?php } ?></tr><?php } ?></tbody></table></div>
      <div class="p-2 small d-flex flex-wrap justify-content-between align-items-center gap-2"><span class="text-body-secondary"><?php if (!empty($result['capped'])) { ?><?= h(number_format((int)$result['count'])) ?> total row(s); showing the first <?= h(number_format((int)($result['display_limit'] ?? MS_SQL_ROWS_DEFAULT))) ?>. Enable <strong>Show all result rows</strong> and run again to display every row.<?php } else { ?><?= h(number_format((int)($result['shown'] ?? count($result['rows'])))) ?> row(s) displayed.<?php } ?></span><?php if (!empty($result['export_token'])) { ?><span class="d-flex flex-wrap align-items-center gap-1"><span class="text-body-secondary me-1">Export all rows:</span><?php foreach (['sql' => 'SQL', 'csv' => 'CSV', 'tsv' => 'TSV'] as $format => $label) { ?><a class="btn btn-secondary btn-sm" href="?download=sql_result&amp;format=<?= h($format) ?>&amp;token=<?= h((string)$result['export_token']) ?>"><i class="fa-solid fa-download me-1"></i><?= h($label) ?></a><?php } ?></span><?php } ?></div><?php
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
  ?><div class="row justify-content-center"><div class="col-lg-5 col-md-7"><?= ms_update_notice() ?><div class="text-center mb-4"><div class="display-5"><i class="fa-solid fa-cube text-primary"></i></div><h1 class="h2 d-flex justify-content-center align-items-center gap-2"><span><?= h(MS_APP_NAME) ?></span><span class="badge text-bg-secondary fs-6 fw-normal">v<?= h(MS_VERSION) ?></span></h1><p class="text-body-secondary">Single-file MySQL/MariaDB administration</p></div>
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
  $defaultLimit=browser_setting_int('mysqlStudioSelectRows',MS_ROWS_PER_PAGE,1,500);$limit=max(1,min(500,(int)g('limit',(string)$defaultLimit)));$showAll=g('show_all')==='1';$page=$showAll?1:max(1,(int)g('p','1'));$offset=($page-1)*$limit;
  $from=' FROM '.qi($table).($where?' WHERE '.implode(' AND ',$where):'');
  $sql='SELECT '.$select.$from.$group.($orderParts?' ORDER BY '.implode(', ',$orderParts):'').($showAll?'':' LIMIT '.$offset.','.$limit);
  $countSql=$group!==''?'SELECT COUNT(*) AS n FROM (SELECT 1'.$from.$group.') ms_groups':'SELECT COUNT(*) AS n'.$from;
  return [$sql,$countSql,$limit,$page,$where,$aggregate!==''&&in_array($aggregate,$validAgg,true),$showAll];
}

function page_select(mysqli $db): void {
  $table=g('table');if(!table_exists($db,$table))throw new RuntimeException('Table or view not found.');$columns=table_columns($db,$table);$meta=db_one($db,'SELECT TABLE_TYPE FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='.qs($db,$table));$editable=($meta['TABLE_TYPE']??'')==='BASE TABLE';
  $relations=[];foreach(db_all($db,"SELECT COLUMN_NAME,REFERENCED_TABLE_NAME,REFERENCED_COLUMN_NAME FROM information_schema.KEY_COLUMN_USAGE WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=".qs($db,$table)." AND REFERENCED_TABLE_NAME IS NOT NULL") as $relation){$relations[$relation['COLUMN_NAME']]=$relation;}
  [$sql,$countSql,$limit,$page,$where,$aggregated,$showAll]=build_select_query($db,$table,$columns);$rows=db_all($db,$sql);$totalRow=db_one($db,$countSql);$total=(int)($totalRow['n']??0);$pages=$showAll?1:max(1,(int)ceil($total/$limit));
  $layoutColumns=array_values(array_map('strval',array_column($columns,'COLUMN_NAME')));$headers=$rows?array_keys($rows[0]):$layoutColumns;$login=is_array($_SESSION['ms_login']??null)?$_SESSION['ms_login']:[];$layoutServer=hash('sha256',(string)($login['host']??'')."\0".(string)($login['port']??'')."\0".(string)($login['socket']??'')."\0".(string)($login['user']??''));$layoutKey=hash('sha256',$layoutServer."\0".selected_db()."\0".$table);$layoutColumnsJson=json_encode($layoutColumns,JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES)?:'[]';
  $actions='<a class="btn btn-secondary" href="?page=structure&amp;table='.urlencode($table).'">Structure</a> ';
  if($showAll){$actions.='<a class="btn btn-secondary" href="'.h(url(['show_all'=>null,'p'=>null,'limit'=>null])).'"><i class="fa-solid fa-layer-group me-1"></i>Use pagination</a> ';}else{$actions.='<a class="btn btn-secondary" data-confirm="Show all '.number_format($total).' rows? Large results can use substantial browser and server memory." href="'.h(url(['show_all'=>'1','p'=>null])).'"><i class="fa-solid fa-list me-1"></i>Show all rows</a> ';}
  if($editable)$actions.='<a class="btn btn-primary" href="?page=row&amp;mode=insert&amp;table='.urlencode($table).'"><i class="fa-solid fa-plus me-1"></i>Insert row</a>';
  title_bar($table,number_format($total).' result(s)',$actions);
  ?><div class="card mb-3 no-print"><div class="card-header"><button class="btn btn-sm btn-secondary" data-bs-toggle="collapse" data-bs-target="#queryBuilder"><i class="fa-solid fa-filter me-1"></i>Search, aggregate, sort and limit</button></div><div class="collapse <?= $where||g('aggregate')!==''||$showAll?'show':'' ?>" id="queryBuilder"><div class="card-body"><form method="get"><input type="hidden" name="page" value="select"><input type="hidden" name="table" value="<?= h($table) ?>"><h3 class="h6">Filters</h3><?php for($i=0;$i<3;$i++){?><div class="row g-2 mb-2"><div class="col-md-3"><select class="form-select" name="filter_col[]"><option value="">Column…</option><?php foreach($columns as $c){$name=$c['COLUMN_NAME'];?><option value="<?= h($name) ?>"<?= (($_GET['filter_col'][$i]??'')===$name)?' selected':'' ?>><?= h($name) ?></option><?php }?></select></div><div class="col-md-2"><select class="form-select" name="filter_op[]"><?php foreach(['=','!=','>','>=','<','<=','contains','starts','ends','regexp','fulltext','null','not_null'] as $op){?><option<?= (($_GET['filter_op'][$i]??'')===$op)?' selected':'' ?>><?= h($op) ?></option><?php }?></select></div><div class="col-md-7"><input class="form-control" name="filter_val[]" value="<?= h($_GET['filter_val'][$i]??'') ?>"></div></div><?php }?><hr><div class="row g-2"><div class="col-md-2"><label class="form-label">Aggregate</label><select class="form-select" name="aggregate"><option value="">None</option><?php foreach(['COUNT','SUM','AVG','MIN','MAX'] as $a){?><option<?= g('aggregate')===$a?' selected':'' ?>><?= $a ?></option><?php }?></select></div><div class="col-md-3"><label class="form-label">Aggregate column</label><select class="form-select" name="aggregate_column"><?php foreach($columns as $c){?><option<?= g('aggregate_column')===$c['COLUMN_NAME']?' selected':'' ?>><?= h($c['COLUMN_NAME']) ?></option><?php }?></select></div><div class="col-md-3"><label class="form-label">Group by</label><select class="form-select" name="group_column"><option value="">None</option><?php foreach($columns as $c){?><option<?= g('group_column')===$c['COLUMN_NAME']?' selected':'' ?>><?= h($c['COLUMN_NAME']) ?></option><?php }?></select></div><div class="col-md-2"><label class="form-label">Rows per page</label><input class="form-control" type="number" name="limit" min="1" max="500" value="<?= h((string)$limit) ?>"></div><div class="col-md-2"><label class="form-label d-block">Display</label><label class="form-check"><input class="form-check-input" type="checkbox" name="show_all" value="1"<?= $showAll?' checked':'' ?>><span class="form-check-label">Show all rows</span></label><div class="form-text">May use substantial memory.</div></div></div><hr><h3 class="h6">Ordering</h3><?php for($i=0;$i<2;$i++){?><div class="row g-2 mb-2"><div class="col-md-4"><select class="form-select" name="order_col[]"><option value="">Column…</option><?php foreach($columns as $c){?><option<?= (($_GET['order_col'][$i]??'')===$c['COLUMN_NAME'])?' selected':'' ?>><?= h($c['COLUMN_NAME']) ?></option><?php }?></select></div><div class="col-md-2"><select class="form-select" name="order_dir[]"><option>ASC</option><option<?= (($_GET['order_dir'][$i]??'')==='DESC')?' selected':'' ?>>DESC</option></select></div></div><?php }?><button class="btn btn-primary">Run query</button> <a class="btn btn-secondary" href="?page=select&amp;table=<?= urlencode($table) ?>">Reset</a></form></div></div></div>
  <form method="post"><input type="hidden" name="action" value="delete_rows"><?= csrf_field() ?><div class="card"><div class="table-scroll"><table class="table table-sm table-striped table-hover align-middle mb-0<?= !$aggregated?' ms-layout-table':'' ?>"<?php if(!$aggregated){ ?> data-ms-table-layout data-ms-layout-key="<?= h($layoutKey) ?>" data-ms-server="<?= h($layoutServer) ?>" data-ms-database="<?= h(selected_db()) ?>" data-ms-table="<?= h($table) ?>" data-ms-columns="<?= h($layoutColumnsJson) ?>"<?php } ?>><thead><tr><?php if($editable&&!$aggregated){?><th data-ms-static-column="selection"><input class="form-check-input" type="checkbox" data-check-all=".row-check"></th><th data-ms-static-column="actions">Actions</th><?php }foreach($headers as $header){?><th<?php if(!$aggregated){ ?> data-ms-column="<?= h((string)$header) ?>" draggable="true"<?php } ?>><?= h($header) ?><?php if(!$aggregated){ ?><span class="ms-col-resizer" data-ms-col-resizer title="Drag to resize"></span><?php } ?></th><?php }?></tr></thead><tbody><?php foreach($rows as $row){$identity=[];foreach(primary_columns($db,$table)?:array_column($columns,'COLUMN_NAME') as $key)$identity[$key]=$row[$key]??null;$encoded=encode_identity($identity);?><tr><?php if($editable&&!$aggregated){?><td data-ms-static-column="selection"><input class="form-check-input row-check" type="checkbox" name="row_id[]" value="<?= h($encoded) ?>"></td><td class="text-nowrap" data-ms-static-column="actions"><a class="btn btn-secondary btn-sm" href="?page=row&amp;mode=edit&amp;table=<?= urlencode($table) ?>&amp;id=<?= urlencode($encoded) ?>"><i class="fa-solid fa-pen"></i></a></td><?php }foreach($row as $name=>$value){$colMeta=null;foreach($columns as $c)if($c['COLUMN_NAME']===$name){$colMeta=$c;break;}?><td<?php if(!$aggregated){ ?> data-ms-column="<?= h((string)$name) ?>"<?php } ?>><?php if($colMeta&&preg_match('/blob|binary/i',(string)$colMeta['DATA_TYPE'])&&$value!==null){?><a href="?download=blob&amp;table=<?= urlencode($table) ?>&amp;column=<?= urlencode((string)$name) ?>&amp;id=<?= urlencode($encoded) ?>"><i class="fa-solid fa-download me-1"></i><?= h(strlen((string)$value)) ?> bytes</a><?php }elseif(isset($relations[$name])&&$value!==null){$rel=$relations[$name];$relUrl='?'.http_build_query(['page'=>'select','table'=>$rel['REFERENCED_TABLE_NAME'],'filter_col'=>[$rel['REFERENCED_COLUMN_NAME']],'filter_op'=>['='],'filter_val'=>[(string)$value]]);?><a href="<?= h($relUrl) ?>" title="Open referenced row"><?= render_value($value) ?> <i class="fa-solid fa-arrow-up-right-from-square small"></i></a><?php }else{echo render_value($value);}?></td><?php }?></tr><?php }?></tbody></table></div><?php if(!$rows){?><div class="p-4 text-center text-body-secondary">No rows.</div><?php }?></div>
  <?php if($editable&&!$aggregated){?><div class="card mt-3 no-print"><div class="card-body"><div class="row g-2 align-items-end"><div class="col-md-auto"><div class="btn-group"><button class="btn btn-danger" data-confirm="Delete the selected rows?">Delete selected</button><button class="btn btn-secondary" name="action" value="clone_selected_prepare"><i class="fa-solid fa-clone me-1"></i>Clone selected</button></div></div><div class="col-md-2"><select class="form-select" name="operation" formaction="<?= h(url()) ?>"><option value="set">Set</option><option value="add">Add number</option><option value="append">Append</option><option value="prepend">Prepend</option><option value="null">Set NULL</option></select></div><div class="col-md-3"><select class="form-select" name="column"><?php foreach($columns as $c){?><option><?= h($c['COLUMN_NAME']) ?></option><?php }?></select></div><div class="col-md-3"><input class="form-control" name="bulk_value" placeholder="Bulk value"></div><div class="col-md-auto"><button class="btn btn-primary" name="action" value="bulk_update">Update selected</button></div></div></div></div><?php }?></form>
  <?php if($showAll){?><div class="alert alert-info mt-3 mb-0 no-print"><i class="fa-solid fa-list me-1"></i>All <?= h(number_format($total)) ?> result(s) are displayed. <a href="<?= h(url(['show_all'=>null,'p'=>null,'limit'=>null])) ?>">Return to paginated view</a>.</div><?php }else{?><nav class="mt-3 no-print"><ul class="pagination"><?php for($i=max(1,$page-3);$i<=min($pages,$page+3);$i++){?><li class="page-item <?= $i===$page?'active':'' ?>"><a class="page-link" href="<?= h(url(['p'=>$i])) ?>"><?= $i ?></a></li><?php }?></ul></nav><?php }?><div class="small text-body-secondary code mt-2">Query: <?= h($sql) ?></div><?php
}

function page_clone_rows(mysqli $db): void {
  $table = g('table');
  $selection = $_SESSION['ms_clone_rows'] ?? null;
  if (!is_array($selection) || (string)($selection['database'] ?? '') !== selected_db() || (string)($selection['table'] ?? '') !== $table) {
    unset($_SESSION['ms_clone_rows']);
    throw new RuntimeException('The selected rows have expired or belong to another database or table. Select them again.');
  }
  if (!table_exists($db, $table)) {
    unset($_SESSION['ms_clone_rows']);
    throw new RuntimeException('Table not found.');
  }
  $ids = isset($selection['ids']) && is_array($selection['ids']) ? $selection['ids'] : [];
  if (!$ids) {
    unset($_SESSION['ms_clone_rows']);
    throw new RuntimeException('No rows are selected for cloning.');
  }
  $columns = table_columns($db, $table);
  $count = count($ids);
  title_bar('Clone selected rows: ' . $table, number_format($count) . ' source row(s)');
  ?><div class="alert alert-info">
    <i class="fa-solid fa-clone me-2"></i>Only fields enabled under <strong>Change</strong> receive a new value. Every other field is copied separately from its original row. Auto-increment and generated columns are recreated by MySQL.
  </div>
  <form method="post" enctype="multipart/form-data">
    <input type="hidden" name="action" value="clone_selected_commit">
    <?= csrf_field() ?>
    <div class="card"><div class="table-responsive"><table class="table align-middle mb-0"><thead><tr><th>Change</th><th>Column</th><th>Type</th><th>New value for every clone</th><th>Options</th></tr></thead><tbody>
    <?php foreach ($columns as $columnIndex => $column) {
      $name = (string)$column['COLUMN_NAME'];
      $extra = (string)$column['EXTRA'];
      $generated = strpos($extra, 'GENERATED') !== false;
      $autoIncrement = strpos($extra, 'auto_increment') !== false;
      $binary = preg_match('/blob|binary/i', (string)$column['DATA_TYPE']) === 1;
      $nullable = (string)$column['IS_NULLABLE'] === 'YES';
      ?><tr>
        <td><?php if (!$generated && !$autoIncrement) { ?><input class="form-check-input" type="checkbox" name="clone_change[<?= h((string)$columnIndex) ?>]" value="1" data-clone-override aria-label="Change <?= h($name) ?>"><?php } else { ?><i class="fa-solid fa-rotate text-body-secondary" title="Generated automatically"></i><?php } ?></td>
        <td><strong><?= h($name) ?></strong><?php if ($column['COLUMN_KEY']) { ?><span class="badge text-bg-primary ms-1"><?= h($column['COLUMN_KEY']) ?></span><?php } ?></td>
        <td class="code small"><?= h($column['COLUMN_TYPE']) ?></td>
        <td>
        <?php if ($autoIncrement) { ?>
          <span class="text-body-secondary">A new auto-increment value will be assigned.</span>
        <?php } elseif ($generated) { ?>
          <span class="text-body-secondary">The value will be generated from the cloned row.</span>
        <?php } elseif ($binary) { ?>
          <input class="form-control mb-1" type="file" name="clone_upload[<?= h((string)$columnIndex) ?>]" data-clone-input disabled>
          <textarea class="form-control code" name="clone_value[<?= h((string)$columnIndex) ?>]" rows="2" placeholder="Or enter textual bytes" data-clone-input disabled></textarea>
        <?php } elseif (in_array($column['DATA_TYPE'], ['text', 'mediumtext', 'longtext', 'json'], true)) { ?>
          <textarea class="form-control code" name="clone_value[<?= h((string)$columnIndex) ?>]" rows="3" placeholder="New value" data-clone-input disabled></textarea>
        <?php } elseif ($column['DATA_TYPE'] === 'enum' && preg_match_all("/'((?:[^'\\\\]|\\\\.)*)'/", (string)$column['COLUMN_TYPE'], $matches)) { ?>
          <select class="form-select" name="clone_value[<?= h((string)$columnIndex) ?>]" data-clone-input disabled><?php foreach ($matches[1] as $option) { $option = stripcslashes($option); ?><option value="<?= h($option) ?>"><?= h($option) ?></option><?php } ?></select>
        <?php } else { ?>
          <input class="form-control" name="clone_value[<?= h((string)$columnIndex) ?>]" placeholder="New value" data-clone-input disabled>
        <?php } ?>
        </td>
        <td class="text-nowrap"><?php if (!$generated && !$autoIncrement) { ?>
          <?php if ($nullable) { ?><label class="d-block"><input class="form-check-input" type="checkbox" name="clone_null[<?= h((string)$columnIndex) ?>]" value="1" data-clone-input disabled> Set NULL</label><?php } ?>
          <label class="d-block"><input class="form-check-input" type="checkbox" name="clone_expression[<?= h((string)$columnIndex) ?>]" value="1" data-clone-input disabled> SQL expression</label>
        <?php } ?></td>
      </tr><?php
    } ?>
    </tbody></table></div></div>
    <div class="alert alert-secondary mt-3 mb-3"><strong>Tip:</strong> a new literal value is applied to every clone. Use an SQL expression such as <code>CONCAT(`name`, ' copy')</code> or <code>`id` + 1000</code> when each cloned value must be derived from its source row. Manual primary or unique keys normally need an override.</div>
    <div class="d-flex flex-wrap gap-2"><button class="btn btn-primary" data-confirm="Create <?= h((string)$count) ?> cloned row(s)?"><i class="fa-solid fa-clone me-1"></i>Clone <?= h((string)$count) ?> row(s)</button><button class="btn btn-secondary" type="submit" name="action" value="clone_selected_cancel" formnovalidate>Cancel</button></div>
  </form>
  <script>
  (()=>{
    document.querySelectorAll('[data-clone-override]').forEach(toggle=>{
      const row=toggle.closest('tr');
      const sync=()=>row.querySelectorAll('[data-clone-input]').forEach(input=>{input.disabled=!toggle.checked;});
      toggle.addEventListener('change',sync);sync();
    });
  })();
  </script><?php
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
  $sqlDefaultRows=browser_setting_int('mysqlStudioSqlRows',MS_SQL_ROWS_DEFAULT,1,100000);
  $tableRows=db_all($db,'SELECT TABLE_NAME,TABLE_TYPE FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() ORDER BY TABLE_NAME');
  $columnRows=db_all($db,'SELECT TABLE_NAME,COLUMN_NAME,COLUMN_TYPE,COLUMN_KEY FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() ORDER BY TABLE_NAME,ORDINAL_POSITION');
  $sqlSchema=['tables'=>[],'columns'=>[]];
  foreach($tableRows as $tableRow){$tableName=(string)$tableRow['TABLE_NAME'];$sqlSchema['tables'][]=['name'=>$tableName,'type'=>(string)$tableRow['TABLE_TYPE']];$sqlSchema['columns'][$tableName]=[];}
  foreach($columnRows as $columnRow){$tableName=(string)$columnRow['TABLE_NAME'];if(!isset($sqlSchema['columns'][$tableName]))$sqlSchema['columns'][$tableName]=[];$sqlSchema['columns'][$tableName][]=['name'=>(string)$columnRow['COLUMN_NAME'],'type'=>(string)$columnRow['COLUMN_TYPE'],'key'=>(string)$columnRow['COLUMN_KEY']];}
  $sqlSchemaJson=json_encode($sqlSchema,JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES|JSON_HEX_TAG|JSON_HEX_AMP|JSON_HEX_APOS|JSON_HEX_QUOT)?:'{"tables":[],"columns":{}}';
  title_bar('SQL command',selected_db());
  ?><div class="card mb-3"><div class="card-body"><form method="post" enctype="multipart/form-data"><input type="hidden" name="action" value="run_sql"><input type="hidden" name="row_limit" value="<?= h((string)$sqlDefaultRows) ?>" data-ms-sql-row-limit><?= csrf_field() ?><label class="form-label">SQL statements</label><textarea class="form-control sql-editor" name="sql" spellcheck="false" autocomplete="off" data-ms-sql-schema-id="ms-sql-schema"><?= h(p('sql',(string)($_SESSION['ms_last_sql']??''))) ?></textarea><script type="application/json" id="ms-sql-schema"><?= $sqlSchemaJson ?></script><div class="form-text mt-2"><i class="fa-solid fa-wand-magic-sparkles me-1"></i>Smart SQL: table suggestions after <code>SELECT</code>, <code>UPDATE</code>, <code>INSERT</code>, <code>FROM</code>, <code>JOIN</code> and related clauses; type <code>table.</code> for columns. Use ↑/↓ and Enter/Tab to accept, Esc to close, Ctrl+Space to reopen suggestions.</div><div class="row g-3 mt-1 align-items-end"><div class="col-md-7"><label class="form-label">Or import a .sql file (maximum 50 MB)</label><input class="form-control" type="file" name="sql_file" accept=".sql,text/sql,text/plain"><label class="mt-3 d-flex align-items-start gap-2"><input class="form-check-input mt-1" type="checkbox" name="show_all" value="1"<?= p('show_all') === '1' ? ' checked' : '' ?>><span><strong>Show all result rows</strong><span class="d-block form-text mt-0">The default display limit is <span data-ms-sql-limit-label><?= h(number_format($sqlDefaultRows)) ?></span> rows. Large results can use substantial browser and server memory.</span></span></label></div><div class="col-md-5 text-md-end"><button class="btn btn-primary"><i class="fa-solid fa-play me-1"></i>Execute <span class="small">Ctrl+Enter</span></button></div></div></form></div></div><?php if($results!==null)render_sql_results($results,$time);
}

function page_export(mysqli $db): void {
  $tables=db_all($db,'SELECT TABLE_NAME,TABLE_TYPE FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() ORDER BY TABLE_NAME');title_bar('Export',selected_db());
  ?><div class="card"><div class="card-body"><form method="get"><input type="hidden" name="download" value="export"><div class="row g-3"><div class="col-md-4"><label class="form-label">Format</label><select class="form-select" name="format"><option value="sql">SQL</option><option value="csv">CSV (one table only)</option><option value="tsv">TSV (one table only)</option></select></div><div class="col-md-8"><label class="form-label">Objects</label><select class="form-select" name="tables[]" multiple size="12"><?php foreach($tables as $t){?><option value="<?= h($t['TABLE_NAME']) ?>" selected><?= h($t['TABLE_NAME'].' · '.$t['TABLE_TYPE']) ?></option><?php }?></select><div class="form-text">Leave all selected to export the database. CSV and TSV require exactly one selection.</div></div><div class="col-12 d-flex gap-4"><label><input class="form-check-input" type="checkbox" name="structure" value="1" checked> Structure, views, routines, triggers and events</label><label><input class="form-check-input" type="checkbox" name="data" value="1" checked> Data</label><label><input class="form-check-input" type="checkbox" name="drop" value="1" checked> Add DROP statements</label></div><div class="col"><button class="btn btn-primary"><i class="fa-solid fa-download me-1"></i>Download export</button></div></div></form></div></div><?php
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

function page_settings(): void {
  $densities = [
    'ultracompact' => ['Ultracompact', 'Maximum information density for large tables.'],
    'compact' => ['Compact', 'More rows and controls without feeling cramped.'],
    'standard' => ['Standard', 'Balanced spacing for everyday administration.'],
    'large' => ['Large', 'Larger controls and generous spacing for touch use.']
  ];
  $schemes = [
    'ocean' => ['Ocean Blue', '#0d6efd', 'Familiar, clear and neutral.'],
    'indigo' => ['Indigo', '#6610f2', 'Technical and focused.'],
    'emerald' => ['Emerald', '#198754', 'Calm, positive and operational.'],
    'teal' => ['Teal', '#0f766e', 'Low-fatigue professional palette.'],
    'ruby' => ['Ruby', '#c92a2a', 'Strong emphasis for critical workflows.'],
    'amber' => ['Amber', '#a65f00', 'Warm, readable and understated.'],
    'violet' => ['Violet', '#7c3aed', 'Distinctive without losing clarity.'],
    'rose' => ['Rose', '#be185d', 'Warm modern interface accent.'],
    'slate' => ['Slate', '#475569', 'Distraction-free administrative look.'],
    'contrast' => ['High Contrast', '#111827', 'Maximum separation and visibility.']
  ];
  $menuItems = [
    'databases' => ['fa-database', 'Databases'],
    'database' => ['fa-table-list', 'Database'],
    'sql' => ['fa-terminal', 'SQL command'],
    'export' => ['fa-file-export', 'Export'],
    'schema' => ['fa-diagram-project', 'Schema'],
    'views' => ['fa-eye', 'Views'],
    'routines' => ['fa-code', 'Routines'],
    'triggers' => ['fa-bolt', 'Triggers'],
    'events' => ['fa-clock', 'Events'],
    'processes' => ['fa-list-check', 'Processes'],
    'users' => ['fa-users-gear', 'Users & rights'],
    'variables' => ['fa-sliders', 'Variables']
  ];
  title_bar('Settings', 'Preferences are saved in this browser and remain active after logout.');
  ?><div id="ms-settings-saved" class="alert alert-success d-none" role="status"><i class="fa-solid fa-circle-check me-2"></i>Settings saved.</div>
  <form id="ms-settings-form">
    <section class="card mb-3"><div class="card-header"><h2 class="h5 mb-0"><i class="fa-solid fa-circle-half-stroke me-2"></i>Appearance mode</h2></div><div class="card-body"><div class="row g-3">
      <div class="col-md-6"><input class="btn-check" type="radio" name="theme" id="theme-light" value="light"><label class="settings-choice card h-100" for="theme-light"><div class="card-body d-flex align-items-center gap-3"><span class="display-6 text-warning"><i class="fa-solid fa-sun"></i></span><span><strong class="d-block">Light</strong><span class="text-body-secondary">Bright background for well-lit environments.</span></span></div></label></div>
      <div class="col-md-6"><input class="btn-check" type="radio" name="theme" id="theme-dark" value="dark"><label class="settings-choice card h-100" for="theme-dark"><div class="card-body d-flex align-items-center gap-3"><span class="display-6 text-primary"><i class="fa-solid fa-moon"></i></span><span><strong class="d-block">Dark</strong><span class="text-body-secondary">Reduced glare for low-light environments.</span></span></div></label></div>
    </div></div></section>

    <section class="card mb-3"><div class="card-header"><h2 class="h5 mb-0"><i class="fa-solid fa-arrows-up-down-left-right me-2"></i>Interface spacing</h2></div><div class="card-body"><div class="row g-3"><?php foreach ($densities as $key => [$label, $description]) { ?>
      <div class="col-sm-6 col-xl-3"><input class="btn-check" type="radio" name="density" id="density-<?= h($key) ?>" value="<?= h($key) ?>"><label class="settings-choice card h-100" for="density-<?= h($key) ?>"><div class="card-body"><strong class="d-block mb-1"><?= h($label) ?></strong><span class="small text-body-secondary"><?= h($description) ?></span></div></label></div>
    <?php } ?></div></div></section>

    <section class="card mb-3"><div class="card-header"><h2 class="h5 mb-0"><i class="fa-solid fa-palette me-2"></i>Color scheme</h2></div><div class="card-body"><div class="row g-3"><?php foreach ($schemes as $key => [$label, $color, $description]) { ?>
      <div class="col-sm-6 col-lg-4 col-xl-3 col-xxl-2"><input class="btn-check" type="radio" name="scheme" id="scheme-<?= h($key) ?>" value="<?= h($key) ?>"><label class="settings-choice card h-100" for="scheme-<?= h($key) ?>"><div class="card-body"><div class="scheme-swatch mb-2" style="--swatch:<?= h($color) ?>"></div><strong class="d-block"><?= h($label) ?></strong><span class="small text-body-secondary"><?= h($description) ?></span></div></label></div>
    <?php } ?></div></div></section>

    <section class="card mb-3"><div class="card-header"><h2 class="h5 mb-0"><i class="fa-solid fa-table-list me-2"></i>Data display</h2></div><div class="card-body"><div class="row g-3">
      <div class="col-md-6"><label class="form-label" for="settings-sql-rows">Default number of rows in Execute SQL</label><input class="form-control" type="number" name="sqlRows" id="settings-sql-rows" min="1" max="100000" step="1" required><div class="form-text">Result sets display this many rows unless “Show all result rows” is enabled. Exports still include the complete result.</div></div>
      <div class="col-md-6"><label class="form-label" for="settings-select-rows">Rows per page in Select</label><input class="form-control" type="number" name="selectRows" id="settings-select-rows" min="1" max="500" step="1" required><div class="form-text">Used as the default page size when browsing a table or view.</div></div>
      <div class="col-12"><div class="border rounded p-3"><div class="form-check form-switch"><input class="form-check-input" type="checkbox" role="switch" name="truncateCells" id="settings-truncate-cells"><label class="form-check-label fw-semibold" for="settings-truncate-cells">Thin, single-line table rows</label></div><div class="form-text ms-4">Keep every displayed cell on one line and replace overflowing text with an ellipsis. The complete value is not changed in the database.</div></div></div>
      <div class="col-12"><div class="alert alert-info mb-0"><i class="fa-solid fa-table-columns me-2"></i>Column order and widths are saved automatically for each server, database and table. A schema mismatch discards that table’s saved layout and restores its natural column layout.</div></div>
    </div></div></section>

    <section class="card mb-3"><div class="card-header d-flex flex-wrap justify-content-between align-items-center gap-2"><h2 class="h5 mb-0"><i class="fa-solid fa-bars me-2"></i>Left menu</h2><div><button class="btn btn-secondary btn-sm" type="button" id="ms-menu-show-all">Show all</button> <button class="btn btn-secondary btn-sm" type="button" id="ms-menu-hide-all">Hide all</button></div></div><div class="card-body"><p class="text-body-secondary">Choose which database tools appear in the left navigation. Settings and Log out always remain visible.</p><div class="row g-2"><?php foreach ($menuItems as $key => [$icon, $label]) { ?>
      <div class="col-md-6 col-xl-4"><label class="border rounded p-3 d-flex align-items-center gap-3 h-100"><input class="form-check-input mt-0" type="checkbox" name="menu[<?= h($key) ?>]" value="1"><i class="fa-solid <?= h($icon) ?> fa-fw text-primary"></i><span><?= h($label) ?></span></label></div>
    <?php } ?></div></div></section>

    <div class="d-flex flex-wrap gap-2"><button class="btn btn-primary" type="submit"><i class="fa-solid fa-floppy-disk me-1"></i>Save settings</button><button class="btn btn-secondary" type="button" id="ms-settings-reset"><i class="fa-solid fa-rotate-left me-1"></i>Restore defaults</button></div>
  </form><?php
}

if (empty($_SESSION['ms_login'])) {
  page_login($error);
  exit;
}

try {
  $db = connect_db(false);
  $page = g('page', selected_db() !== '' ? 'database' : 'databases');
  $allowedPages = ['databases','database','create_table','structure','select','clone_rows','row','sql','export','schema','views','routines','triggers','events','processes','users','variables','settings'];
  if (!in_array($page, $allowedPages, true)) {
    $page = selected_db() !== '' ? 'database' : 'databases';
  }
  $needsDatabase = !in_array($page, ['databases','processes','users','variables','settings'], true);
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
  echo ms_update_notice();
  if ($error !== '') {
    echo '<div class="alert alert-danger">' . h($error) . '</div>';
  }
  switch ($page) {
    case 'databases': page_databases($db); break;
    case 'database': page_database($db); break;
    case 'create_table': page_create_table($db); break;
    case 'structure': page_structure($db); break;
    case 'select': page_select($db); break;
    case 'clone_rows': page_clone_rows($db); break;
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
    case 'settings': page_settings(); break;
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
