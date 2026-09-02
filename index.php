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
const MS_VERSION = '1.12.0';
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
header("Content-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; font-src 'self' https://cdnjs.cloudflare.com; img-src 'self' data: blob: https: http:");

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

function ms_raw_db_view(): bool {
  $settings = ms_profile_settings();
  return !empty($settings['rawDbView']);
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

function ms_allowed_pages(): array {
  return ['databases','database','create_table','structure','select','clone_rows','row','sql','export','schema','views','routines','triggers','events','processes','users','variables','settings'];
}

function ms_clean_navigation_value($value, int $depth = 0) {
  if ($depth > 4) {
    return null;
  }
  if (is_scalar($value) || $value === null) {
    return $value === null ? '' : (string)$value;
  }
  if (!is_array($value)) {
    return null;
  }
  $clean = [];
  foreach ($value as $key => $item) {
    if (!is_int($key) && !is_string($key)) {
      continue;
    }
    $cleaned = ms_clean_navigation_value($item, $depth + 1);
    if ($cleaned !== null) {
      $clean[$key] = $cleaned;
    }
  }
  return $clean;
}

function ms_navigation_query(array $source): array {
  $page = isset($source['page']) && !is_array($source['page']) ? (string)$source['page'] : '';
  if ($page === '' || !in_array($page, ms_allowed_pages(), true)) {
    return [];
  }

  $clean = [];
  foreach ($source as $key => $value) {
    $key = (string)$key;
    if ($key === '' || in_array($key, ['download', 'ajax', 'ms_check_update'], true)) {
      continue;
    }
    $cleaned = ms_clean_navigation_value($value);
    if ($cleaned !== null) {
      $clean[$key] = $cleaned;
    }
  }
  $clean['page'] = $page;
  return $clean;
}

function ms_encode_navigation(array $query): string {
  $query = ms_navigation_query($query);
  if (!$query) {
    return '';
  }
  $json = json_encode($query, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
  if (!is_string($json) || $json === '') {
    return '';
  }
  return rtrim(strtr(base64_encode($json), '+/', '-_'), '=');
}

function ms_decode_navigation(string $encoded): array {
  $encoded = trim($encoded);
  if ($encoded === '' || strlen($encoded) > 32768 || preg_match('/^[A-Za-z0-9_-]+$/', $encoded) !== 1) {
    return [];
  }
  $padding = strlen($encoded) % 4;
  if ($padding !== 0) {
    $encoded .= str_repeat('=', 4 - $padding);
  }
  $json = base64_decode(strtr($encoded, '-_', '+/'), true);
  if (!is_string($json) || $json === '') {
    return [];
  }
  $decoded = json_decode($json, true);
  return is_array($decoded) ? ms_navigation_query($decoded) : [];
}

function ms_navigation_requires_database(array $query): bool {
  $page = isset($query['page']) && !is_array($query['page']) ? (string)$query['page'] : '';
  return $page !== '' && !in_array($page, ['databases','processes','users','variables','settings'], true);
}

function ms_go_to_query(array $query, string $flash = '', string $type = 'success'): void {
  $query = ms_navigation_query($query);
  if (!$query) {
    $query = ['page' => 'databases'];
  }
  if ($flash !== '') {
    $_SESSION['ms_flash'] = [$type, $flash];
  }
  header('Location: ?' . http_build_query($query));
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

/**
 * Profile-based configuration.
 *
 * This is a deliberately new format. No legacy configuration is imported or
 * interpreted. Every configurable preference lives below a named profile.
 */
function ms_profile_config_file(): string {
  return ms_update_runtime_file('profiles.json');
}

function ms_profile_config_lock_file(): string {
  return ms_update_runtime_file('profiles.lock');
}

function ms_server_config_key(): string {
  $login = isset($_SESSION['ms_login']) && is_array($_SESSION['ms_login']) ? $_SESSION['ms_login'] : [];
  return hash('sha256',
    (string)($login['host'] ?? '') . "\0" .
    (string)($login['port'] ?? '') . "\0" .
    (string)($login['socket'] ?? '') . "\0" .
    (string)($login['user'] ?? '')
  );
}

function ms_profile_default_settings(): array {
  return [
    'theme' => 'light',
    'density' => 'standard',
    'scheme' => 'ocean',
    'sqlRows' => 1000,
    'selectRows' => 50,
    'paginationPosition' => 'bottom',
    'truncateCells' => false,
    'rawDbView' => false,
    'schemaColumnWidth' => 3,
    'menu' => [
      'databases' => true,
      'database' => true,
      'sql' => true,
      'export' => true,
      'schema' => true,
      'views' => true,
      'routines' => true,
      'triggers' => true,
      'events' => true,
      'processes' => true,
      'users' => true,
      'variables' => true
    ]
  ];
}

function ms_profile_default_data(): array {
  return ['settings' => ms_profile_default_settings(), 'servers' => []];
}

function ms_profile_normalize_settings(array $source): array {
  $defaults = ms_profile_default_settings();
  $themes = ['light', 'dark'];
  $densities = ['ultracompact', 'compact', 'standard', 'large'];
  $schemes = ['ocean','indigo','emerald','teal','ruby','amber','violet','rose','slate','contrast'];
  $pagination = ['top','bottom','both'];
  $settings = $defaults;
  $settings['theme'] = in_array((string)($source['theme'] ?? ''), $themes, true) ? (string)$source['theme'] : $defaults['theme'];
  $settings['density'] = in_array((string)($source['density'] ?? ''), $densities, true) ? (string)$source['density'] : $defaults['density'];
  $settings['scheme'] = in_array((string)($source['scheme'] ?? ''), $schemes, true) ? (string)$source['scheme'] : $defaults['scheme'];
  $settings['sqlRows'] = max(1, min(100000, (int)($source['sqlRows'] ?? $defaults['sqlRows'])));
  $settings['selectRows'] = max(1, min(500, (int)($source['selectRows'] ?? $defaults['selectRows'])));
  $settings['paginationPosition'] = in_array((string)($source['paginationPosition'] ?? ''), $pagination, true) ? (string)$source['paginationPosition'] : $defaults['paginationPosition'];
  $settings['truncateCells'] = !empty($source['truncateCells']);
  $settings['rawDbView'] = !empty($source['rawDbView']);
  $schemaWidth = (int)($source['schemaColumnWidth'] ?? $defaults['schemaColumnWidth']);
  $settings['schemaColumnWidth'] = in_array($schemaWidth, [2,3,4,6,12], true) ? $schemaWidth : $defaults['schemaColumnWidth'];
  $sourceMenu = isset($source['menu']) && is_array($source['menu']) ? $source['menu'] : [];
  foreach ($defaults['menu'] as $key => $enabled) {
    $settings['menu'][$key] = !array_key_exists($key, $sourceMenu) || $sourceMenu[$key] !== false;
  }
  return $settings;
}

function ms_profile_config_read(): array {
  $empty = ['version' => 2, 'profiles' => ['Default' => ms_profile_default_data()]];
  $raw = @file_get_contents(ms_profile_config_file());
  if (!is_string($raw) || trim($raw) === '') {
    return $empty;
  }
  $decoded = json_decode($raw, true);
  if (!is_array($decoded) || (int)($decoded['version'] ?? 0) !== 2 || !isset($decoded['profiles']) || !is_array($decoded['profiles'])) {
    return $empty;
  }
  if (!isset($decoded['profiles']['Default']) || !is_array($decoded['profiles']['Default'])) {
    $decoded['profiles']['Default'] = ms_profile_default_data();
  }
  foreach ($decoded['profiles'] as $name => $profile) {
    if (!is_string($name) || $name === '' || !is_array($profile)) {
      unset($decoded['profiles'][$name]);
      continue;
    }
    $decoded['profiles'][$name]['settings'] = ms_profile_normalize_settings(isset($profile['settings']) && is_array($profile['settings']) ? $profile['settings'] : []);
    if (!isset($decoded['profiles'][$name]['servers']) || !is_array($decoded['profiles'][$name]['servers'])) {
      $decoded['profiles'][$name]['servers'] = [];
    }
  }
  $decoded['version'] = 2;
  return $decoded;
}

function ms_profile_config_ensure(): void {
  if (is_file(ms_profile_config_file())) return;
  ms_profile_config_mutate(static function (array $config): array { return $config; });
}

function ms_profile_config_mutate(callable $mutator): void {
  $lock = @fopen(ms_profile_config_lock_file(), 'c');
  if ($lock === false) {
    throw new RuntimeException('Unable to open the profile configuration lock file.');
  }
  if (!@flock($lock, LOCK_EX)) {
    fclose($lock);
    throw new RuntimeException('Unable to lock the profile configuration.');
  }
  try {
    $config = ms_profile_config_read();
    $updated = $mutator($config);
    if (!is_array($updated)) {
      throw new RuntimeException('The profile configuration update is invalid.');
    }
    $updated['version'] = 2;
    if (!isset($updated['profiles']) || !is_array($updated['profiles'])) {
      $updated['profiles'] = [];
    }
    if (!isset($updated['profiles']['Default']) || !is_array($updated['profiles']['Default'])) {
      $updated['profiles']['Default'] = ms_profile_default_data();
    }
    $json = json_encode($updated, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    if (!is_string($json)) {
      throw new RuntimeException('Unable to encode the profile configuration.');
    }
    $path = ms_profile_config_file();
    $temporary = $path . '.tmp-' . bin2hex(random_bytes(5));
    $written = @file_put_contents($temporary, $json . "\n", LOCK_EX);
    if ($written === false) {
      @unlink($temporary);
      throw new RuntimeException('Unable to write the profile configuration.');
    }
    if (!@rename($temporary, $path)) {
      @unlink($temporary);
      throw new RuntimeException('Unable to replace the profile configuration.');
    }
  } finally {
    @flock($lock, LOCK_UN);
    fclose($lock);
  }
}

function ms_profile_names(): array {
  $config = ms_profile_config_read();
  $names = array_values(array_map('strval', array_keys($config['profiles'])));
  usort($names, static function (string $a, string $b): int {
    if ($a === 'Default') return -1;
    if ($b === 'Default') return 1;
    return strcasecmp($a, $b);
  });
  return $names;
}

function ms_profile_validate_name(string $name): string {
  $name = trim($name);
  if ($name === '' || preg_match('/[\x00-\x1F\x7F]/', $name) === 1) {
    throw new RuntimeException('Profile name is required.');
  }
  $length = preg_match_all('/./us', $name, $chars);
  if ($length === false || $length > 80) {
    throw new RuntimeException('Profile name must be valid UTF-8 and 80 characters or fewer.');
  }
  return $name;
}

function ms_active_profile_name(): string {
  $config = ms_profile_config_read();
  $candidate = isset($_SESSION['ms_profile']) ? (string)$_SESSION['ms_profile'] : '';
  if ($candidate === '' && isset($_COOKIE['mysqlStudioProfile']) && !is_array($_COOKIE['mysqlStudioProfile'])) {
    $candidate = (string)$_COOKIE['mysqlStudioProfile'];
  }
  if ($candidate === '' || !isset($config['profiles'][$candidate])) {
    $candidate = 'Default';
  }
  $_SESSION['ms_profile'] = $candidate;
  return $candidate;
}

function ms_set_active_profile(string $name): void {
  $name = ms_profile_validate_name($name);
  $config = ms_profile_config_read();
  if (!isset($config['profiles'][$name])) {
    throw new RuntimeException('Profile not found.');
  }
  $_SESSION['ms_profile'] = $name;
  $secure = !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off';
  setcookie('mysqlStudioProfile', $name, time() + 31536000, '/', '', $secure, true);
}

function ms_profile_settings(): array {
  $config = ms_profile_config_read();
  $name = ms_active_profile_name();
  $profile = isset($config['profiles'][$name]) && is_array($config['profiles'][$name]) ? $config['profiles'][$name] : ms_profile_default_data();
  return ms_profile_normalize_settings(isset($profile['settings']) && is_array($profile['settings']) ? $profile['settings'] : []);
}

function ms_profile_setting_int(string $key, int $default, int $minimum, int $maximum): int {
  $settings = ms_profile_settings();
  return max($minimum, min($maximum, (int)($settings[$key] ?? $default)));
}

function ms_profile_update_settings(array $settings): void {
  $name = ms_active_profile_name();
  $normalized = ms_profile_normalize_settings($settings);
  ms_profile_config_mutate(static function (array $config) use ($name, $normalized): array {
    if (!isset($config['profiles'][$name]) || !is_array($config['profiles'][$name])) {
      $config['profiles'][$name] = ms_profile_default_data();
    }
    $config['profiles'][$name]['settings'] = $normalized;
    return $config;
  });
}

function ms_profile_create(string $name): void {
  $name = ms_profile_validate_name($name);
  ms_profile_config_mutate(static function (array $config) use ($name): array {
    foreach (array_keys($config['profiles']) as $existing) {
      if (strcasecmp((string)$existing, $name) === 0) {
        throw new RuntimeException('A profile with that name already exists.');
      }
    }
    $config['profiles'][$name] = ms_profile_default_data();
    return $config;
  });
  ms_set_active_profile($name);
}

function ms_profile_rename(string $newName): void {
  $oldName = ms_active_profile_name();
  if ($oldName === 'Default') {
    throw new RuntimeException('The Default profile cannot be renamed.');
  }
  $newName = ms_profile_validate_name($newName);
  ms_profile_config_mutate(static function (array $config) use ($oldName, $newName): array {
    foreach (array_keys($config['profiles']) as $existing) {
      if ((string)$existing !== $oldName && strcasecmp((string)$existing, $newName) === 0) {
        throw new RuntimeException('A profile with that name already exists.');
      }
    }
    if (!isset($config['profiles'][$oldName])) {
      throw new RuntimeException('Profile not found.');
    }
    $profile = $config['profiles'][$oldName];
    unset($config['profiles'][$oldName]);
    $config['profiles'][$newName] = $profile;
    return $config;
  });
  ms_set_active_profile($newName);
}

function ms_profile_delete_active(): void {
  $name = ms_active_profile_name();
  if ($name === 'Default') {
    throw new RuntimeException('The Default profile cannot be deleted.');
  }
  ms_profile_config_mutate(static function (array $config) use ($name): array {
    unset($config['profiles'][$name]);
    return $config;
  });
  ms_set_active_profile('Default');
}

function ms_profile_reset_active(): void {
  $name = ms_active_profile_name();
  ms_profile_config_mutate(static function (array $config) use ($name): array {
    $config['profiles'][$name] = ms_profile_default_data();
    return $config;
  });
}

function ms_profile_database_config(string $database): array {
  $config = ms_profile_config_read();
  $profile = ms_active_profile_name();
  $serverKey = ms_server_config_key();
  $databaseConfig = $config['profiles'][$profile]['servers'][$serverKey]['databases'][$database] ?? [];
  return is_array($databaseConfig) ? $databaseConfig : [];
}

function ms_profile_update_database(string $database, callable $mutator): void {
  $profile = ms_active_profile_name();
  ms_profile_config_mutate(static function (array $config) use ($profile, $database, $mutator): array {
    $serverKey = ms_server_config_key();
    if (!isset($config['profiles'][$profile]) || !is_array($config['profiles'][$profile])) {
      $config['profiles'][$profile] = ms_profile_default_data();
    }
    if (!isset($config['profiles'][$profile]['servers'][$serverKey]) || !is_array($config['profiles'][$profile]['servers'][$serverKey])) {
      $config['profiles'][$profile]['servers'][$serverKey] = ['databases' => []];
    }
    if (!isset($config['profiles'][$profile]['servers'][$serverKey]['databases']) || !is_array($config['profiles'][$profile]['servers'][$serverKey]['databases'])) {
      $config['profiles'][$profile]['servers'][$serverKey]['databases'] = [];
    }
    $current = $config['profiles'][$profile]['servers'][$serverKey]['databases'][$database] ?? [];
    if (!is_array($current)) $current = [];
    if (!isset($current['tables']) || !is_array($current['tables'])) $current['tables'] = [];
    if (!isset($current['hidden_sidebar']) || !is_array($current['hidden_sidebar'])) $current['hidden_sidebar'] = [];
    $current = $mutator($current);
    if (empty($current['tables'])) unset($current['tables']);
    if (empty($current['hidden_sidebar'])) unset($current['hidden_sidebar']);
    if ($current) {
      $config['profiles'][$profile]['servers'][$serverKey]['databases'][$database] = $current;
    } else {
      unset($config['profiles'][$profile]['servers'][$serverKey]['databases'][$database]);
    }
    return $config;
  });
}

function ms_profile_table_config(string $database, string $table): array {
  $databaseConfig = ms_profile_database_config($database);
  $tableConfig = $databaseConfig['tables'][$table] ?? [];
  return is_array($tableConfig) ? $tableConfig : [];
}

function ms_profile_update_table(string $database, string $table, callable $mutator): void {
  ms_profile_update_database($database, static function (array $databaseConfig) use ($table, $mutator): array {
    $current = $databaseConfig['tables'][$table] ?? [];
    if (!is_array($current)) $current = [];
    $current = $mutator($current);
    if ($current) $databaseConfig['tables'][$table] = $current;
    else unset($databaseConfig['tables'][$table]);
    return $databaseConfig;
  });
}

function ms_profile_hidden_sidebar(string $database): array {
  $databaseConfig = ms_profile_database_config($database);
  $hidden = isset($databaseConfig['hidden_sidebar']) && is_array($databaseConfig['hidden_sidebar']) ? $databaseConfig['hidden_sidebar'] : [];
  return array_filter($hidden, static function ($value): bool { return $value === true; });
}

function ms_profile_set_sidebar_visibility(string $database, string $table, bool $visible): void {
  ms_profile_update_database($database, static function (array $databaseConfig) use ($table, $visible): array {
    if (!isset($databaseConfig['hidden_sidebar']) || !is_array($databaseConfig['hidden_sidebar'])) $databaseConfig['hidden_sidebar'] = [];
    if ($visible) unset($databaseConfig['hidden_sidebar'][$table]);
    else $databaseConfig['hidden_sidebar'][$table] = true;
    return $databaseConfig;
  });
}

function ms_profile_table_layout(string $database, string $table): array {
  $tableConfig = ms_profile_table_config($database, $table);
  $layout = $tableConfig['layout'] ?? [];
  return is_array($layout) ? $layout : [];
}

function ms_profile_set_table_order(string $database, string $table, array $order, array $columns): void {
  $allowed = array_values(array_map('strval', $columns));
  $clean = [];
  foreach ($order as $column) {
    $column = (string)$column;
    if (in_array($column, $allowed, true) && !in_array($column, $clean, true)) $clean[] = $column;
  }
  foreach ($allowed as $column) if (!in_array($column, $clean, true)) $clean[] = $column;
  ms_profile_update_table($database, $table, static function (array $tableConfig) use ($clean): array {
    $layout = isset($tableConfig['layout']) && is_array($tableConfig['layout']) ? $tableConfig['layout'] : [];
    $layout['order'] = $clean;
    $tableConfig['layout'] = $layout;
    return $tableConfig;
  });
}

function ms_profile_set_table_widths(string $database, string $table, array $widths, array $columns): void {
  $allowed = array_values(array_map('strval', $columns));
  $clean = [];
  foreach ($widths as $column => $width) {
    $column = (string)$column;
    $numeric = (int)$width;
    if (in_array($column, $allowed, true) && $numeric >= 48 && $numeric <= 1200) $clean[$column] = $numeric;
  }
  ms_profile_update_table($database, $table, static function (array $tableConfig) use ($clean): array {
    $layout = isset($tableConfig['layout']) && is_array($tableConfig['layout']) ? $tableConfig['layout'] : [];
    $existing = isset($layout['widths']) && is_array($layout['widths']) ? $layout['widths'] : [];
    foreach ($clean as $column => $width) $existing[$column] = $width;
    $layout['widths'] = $existing;
    $tableConfig['layout'] = $layout;
    return $tableConfig;
  });
}

function ms_profile_table_saved_searches(string $database, string $table): array {
  $tableConfig = ms_profile_table_config($database, $table);
  $searches = $tableConfig['saved_searches'] ?? [];
  if (!is_array($searches)) return [];
  uksort($searches, 'strnatcasecmp');
  return $searches;
}

function ms_saved_search_name(string $name): string {
  $name = trim($name);
  $length = preg_match_all('/./us', $name, $chars);
  if ($name === '' || $length === false || $length > 100) {
    throw new RuntimeException('Saved search name is required and must be 100 characters or fewer.');
  }
  return $name;
}

function ms_saved_search_normalize(array $source, array $columnNames): array {
  $allowed = array_values(array_map('strval', $columnNames));
  $result = [];
  $filterCols = isset($source['filter_col']) && is_array($source['filter_col']) ? array_slice($source['filter_col'], 0, 3) : [];
  $filterOps = isset($source['filter_op']) && is_array($source['filter_op']) ? array_slice($source['filter_op'], 0, 3) : [];
  $filterVals = isset($source['filter_val']) && is_array($source['filter_val']) ? array_slice($source['filter_val'], 0, 3) : [];
  $validOps = ['=','!=','>','>=','<','<=','contains','starts','ends','regexp','fulltext','null','not_null'];
  $outCols = []; $outOps = []; $outVals = [];
  for ($i = 0; $i < 3; $i++) {
    $column = (string)($filterCols[$i] ?? '');
    if ($column === '' || !in_array($column, $allowed, true)) continue;
    $op = (string)($filterOps[$i] ?? '=');
    if (!in_array($op, $validOps, true)) $op = '=';
    $outCols[] = $column; $outOps[] = $op; $outVals[] = (string)($filterVals[$i] ?? '');
  }
  if ($outCols) {
    $result['filter_col'] = $outCols; $result['filter_op'] = $outOps; $result['filter_val'] = $outVals;
  }
  $aggregate = strtoupper((string)($source['aggregate'] ?? ''));
  if (in_array($aggregate, ['COUNT','SUM','AVG','MIN','MAX'], true)) {
    $aggregateColumn = (string)($source['aggregate_column'] ?? '');
    if (in_array($aggregateColumn, $allowed, true)) {
      $result['aggregate'] = $aggregate;
      $result['aggregate_column'] = $aggregateColumn;
      $group = (string)($source['group_column'] ?? '');
      if ($group !== '' && in_array($group, $allowed, true)) $result['group_column'] = $group;
    }
  }
  $orderCols = isset($source['order_col']) && is_array($source['order_col']) ? array_slice($source['order_col'], 0, 2) : [];
  $orderDirs = isset($source['order_dir']) && is_array($source['order_dir']) ? array_slice($source['order_dir'], 0, 2) : [];
  $cleanOrderCols = []; $cleanOrderDirs = [];
  foreach ($orderCols as $i => $column) {
    $column = (string)$column;
    if (!in_array($column, $allowed, true)) continue;
    $cleanOrderCols[] = $column;
    $cleanOrderDirs[] = strtoupper((string)($orderDirs[$i] ?? 'ASC')) === 'DESC' ? 'DESC' : 'ASC';
  }
  if ($cleanOrderCols) {
    $result['order_col'] = $cleanOrderCols; $result['order_dir'] = $cleanOrderDirs;
  }
  $result['limit'] = max(1, min(500, (int)($source['limit'] ?? ms_profile_setting_int('selectRows', MS_ROWS_PER_PAGE, 1, 500))));
  if (!empty($source['show_all']) && (string)$source['show_all'] === '1') $result['show_all'] = '1';
  return $result;
}

function ms_profile_save_search(string $database, string $table, string $name, array $query): void {
  $name = ms_saved_search_name($name);
  ms_profile_update_table($database, $table, static function (array $tableConfig) use ($name, $query): array {
    if (!isset($tableConfig['saved_searches']) || !is_array($tableConfig['saved_searches'])) $tableConfig['saved_searches'] = [];
    $tableConfig['saved_searches'][$name] = $query;
    return $tableConfig;
  });
}

function ms_profile_delete_search(string $database, string $table, string $name): void {
  ms_profile_update_table($database, $table, static function (array $tableConfig) use ($name): array {
    if (isset($tableConfig['saved_searches']) && is_array($tableConfig['saved_searches'])) {
      unset($tableConfig['saved_searches'][$name]);
      if (!$tableConfig['saved_searches']) unset($tableConfig['saved_searches']);
    }
    return $tableConfig;
  });
}

function ms_column_view_table_config(string $database, string $table): array {
  $tableConfig = ms_profile_table_config($database, $table);
  foreach (['hidden', 'images', 'soft_fk', 'formats', 'labels'] as $key) {
    if (!isset($tableConfig[$key]) || !is_array($tableConfig[$key])) $tableConfig[$key] = [];
  }
  return $tableConfig;
}

function ms_column_view_database_config(string $database): array {
  return ms_profile_database_config($database);
}

function ms_column_view_update_table(string $database, string $table, callable $mutator): void {
  ms_profile_update_table($database, $table, static function (array $current) use ($mutator): array {
    foreach (['hidden', 'images', 'soft_fk', 'formats', 'labels'] as $key) {
      if (!isset($current[$key]) || !is_array($current[$key])) $current[$key] = [];
    }
    $current = $mutator($current);
    foreach (['hidden', 'images', 'soft_fk', 'formats', 'labels'] as $key) if (empty($current[$key])) unset($current[$key]);
    return $current;
  });
}

function ms_column_view_hide(string $database, string $table, string $column, bool $hidden): void {
  ms_column_view_update_table($database, $table, static function (array $config) use ($column, $hidden): array {
    if ($hidden) $config['hidden'][$column] = true;
    else unset($config['hidden'][$column]);
    return $config;
  });
}

function ms_column_view_show_all(string $database): void {
  ms_profile_update_database($database, static function (array $databaseConfig): array {
    $tables = isset($databaseConfig['tables']) && is_array($databaseConfig['tables']) ? $databaseConfig['tables'] : [];
    foreach ($tables as $table => $tableConfig) {
      if (!is_array($tableConfig)) continue;
      unset($tableConfig['hidden']);
      if ($tableConfig) $databaseConfig['tables'][$table] = $tableConfig;
      else unset($databaseConfig['tables'][$table]);
    }
    return $databaseConfig;
  });
}

function ms_column_view_set_image(string $database, string $table, string $column, ?array $rule): void {
  ms_column_view_update_table($database, $table, static function (array $config) use ($column, $rule): array {
    if ($rule === null) unset($config['images'][$column]);
    else { $config['images'][$column] = $rule; unset($config['soft_fk'][$column], $config['formats'][$column]); }
    return $config;
  });
}

function ms_column_view_set_soft_fk(string $database, string $table, string $column, ?array $rule): void {
  ms_column_view_update_table($database, $table, static function (array $config) use ($column, $rule): array {
    if ($rule === null) unset($config['soft_fk'][$column]);
    else { $config['soft_fk'][$column] = $rule; unset($config['images'][$column], $config['formats'][$column]); }
    return $config;
  });
}

function ms_column_view_set_format(string $database, string $table, string $column, ?array $rule): void {
  ms_column_view_update_table($database, $table, static function (array $config) use ($column, $rule): array {
    if ($rule === null) unset($config['formats'][$column]);
    else { $config['formats'][$column] = $rule; unset($config['images'][$column], $config['soft_fk'][$column]); }
    return $config;
  });
}

function ms_column_view_set_label(string $database, string $table, string $column, ?string $label): void {
  ms_column_view_update_table($database, $table, static function (array $config) use ($column, $label): array {
    if ($label === null || $label === '') unset($config['labels'][$column]);
    else $config['labels'][$column] = $label;
    return $config;
  });
}

function ms_column_view_clear_display(string $database, string $table, string $column): void {
  ms_column_view_update_table($database, $table, static function (array $config) use ($column): array {
    unset($config['formats'][$column], $config['images'][$column], $config['soft_fk'][$column]);
    return $config;
  });
}

function ms_safe_image_base_url(string $url): bool {
  if ($url === '' || preg_match('/[\x00-\x1F\x7F<>"\']/', $url) === 1) {
    return false;
  }
  return preg_match('#\A(?:https?://|/|\./|\.\./)#i', $url) === 1;
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

function ms_update_set_notice_now(string $message, string $type = 'info'): void {
  $_SESSION['ms_update_notice'] = [$type, $message];
}

function ms_update_redirect_without_force(): void {
  $query = $_GET;
  unset($query['ms_check_update']);
  $path = (string)(parse_url((string)($_SERVER['REQUEST_URI'] ?? ''), PHP_URL_PATH) ?? '');
  if ($path === '') {
    $path = (string)($_SERVER['PHP_SELF'] ?? './');
  }
  $location = $path . ($query ? '?' . http_build_query($query) : '');
  $location = str_replace(["\r", "\n"], '', $location);
  session_write_close();
  header('Location: ' . ($location !== '' ? $location : './'));
  exit;
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

  // A manual check is intentionally available only to an authenticated user.
  // It bypasses the normal six-hour cache and always reports the result.
  $force = !empty($_SESSION['ms_login']) && g('ms_check_update') === '1';
  $now = time();
  $cache = ms_update_cache_read();
  $checkedAt = (int)($cache['checked_at'] ?? 0);

  if (!$force && $checkedAt > 0 && ($now - $checkedAt) < MS_UPDATE_CHECK_SECONDS) {
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
    if ($force) {
      ms_update_set_notice_now('The update check could not start because the updater lock file could not be opened.', 'warning');
      ms_update_redirect_without_force();
    }
    return;
  }
  if (!@flock($lock, LOCK_EX | LOCK_NB)) {
    fclose($lock);
    if ($force) {
      ms_update_set_notice_now('Another update check is already in progress. Please try again.', 'info');
      ms_update_redirect_without_force();
    }
    return;
  }

  try {
    // Another request may have completed the automatic check just before this
    // request acquired the lock. A forced check deliberately ignores this.
    if (!$force) {
      $cache = ms_update_cache_read();
      $checkedAt = (int)($cache['checked_at'] ?? 0);
      if ($checkedAt > 0 && ($now - $checkedAt) < MS_UPDATE_CHECK_SECONDS) {
        return;
      }
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
      if ($force) {
        ms_update_set_notice_now('The update check failed because GitHub could not be reached.', 'warning');
      }
    } else {
      $remoteVersion = ms_update_extract_version($source);
      if ($remoteVersion === null) {
        ms_update_cache_write([
          'checked_at' => $now,
          'local_version' => MS_VERSION,
          'remote_version' => '',
          'status' => 'check_failed',
          'message' => 'The remote version could not be determined.'
        ]);
        if ($force) {
          ms_update_set_notice_now('GitHub was reached, but the remote version could not be determined.', 'warning');
        }
      } elseif (!version_compare($remoteVersion, MS_VERSION, '>')) {
        ms_update_cache_write([
          'checked_at' => $now,
          'local_version' => MS_VERSION,
          'remote_version' => $remoteVersion,
          'status' => 'current',
          'message' => ''
        ]);
        if ($force) {
          $message = version_compare(MS_VERSION, $remoteVersion, '>')
            ? 'This installation is newer than the version currently published on GitHub. Installed: ' . MS_VERSION . '; GitHub: ' . $remoteVersion . '.'
            : 'You are running the latest version of ' . MS_APP_NAME . ' (' . MS_VERSION . ').';
          ms_update_set_notice_now($message, 'success');
        }
      } else {
        $installError = ms_update_install($source, $remoteVersion);
        if ($installError !== null) {
          ms_update_cache_write([
            'checked_at' => $now,
            'local_version' => MS_VERSION,
            'remote_version' => $remoteVersion,
            'status' => 'install_failed',
            'message' => $installError
          ]);
          if ($force) {
            ms_update_set_notice_now(
              MS_APP_NAME . ' ' . $remoteVersion . ' is available, but the automatic update could not be installed: ' . $installError,
              'warning'
            );
          } else {
            ms_update_set_notice(
              'update-failed-' . $remoteVersion,
              MS_APP_NAME . ' ' . $remoteVersion . ' is available, but the automatic update could not be installed: ' . $installError,
              'warning'
            );
          }
        } else {
          ms_update_cache_write([
            'checked_at' => $now,
            'local_version' => $remoteVersion,
            'remote_version' => $remoteVersion,
            'status' => 'updated',
            'message' => ''
          ]);
          ms_update_set_notice_now(
            MS_APP_NAME . ' was automatically updated from version ' . MS_VERSION . ' to ' . $remoteVersion . '.',
            'success'
          );
        }
      }
    }
  } finally {
    @flock($lock, LOCK_UN);
    fclose($lock);
  }

  // Manual checks always return to the same page with the force flag removed.
  // Successful automatic updates also reload so the newly installed PHP file
  // is the code handling the next request.
  if ($force) {
    ms_update_redirect_without_force();
  }

  $latestCache = ms_update_cache_read();
  if (($latestCache['status'] ?? '') === 'updated' && (string)($latestCache['local_version'] ?? '') !== MS_VERSION) {
    ms_update_redirect_without_force();
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


function ms_soft_fk_maps(mysqli $db, array $rows, array $rules): array {
  $maps = [];
  if (!$rows || !$rules) {
    return $maps;
  }
  foreach ($rules as $sourceColumn => $rule) {
    if (!is_array($rule)) {
      continue;
    }
    $targetTable = (string)($rule['table'] ?? '');
    $idColumn = (string)($rule['id_column'] ?? '');
    $valueColumn = (string)($rule['value_column'] ?? '');
    if ($targetTable === '' || $idColumn === '' || $valueColumn === '' || !table_exists($db, $targetTable)) {
      continue;
    }
    $targetColumns = array_column(table_columns($db, $targetTable), 'COLUMN_NAME');
    if (!in_array($idColumn, $targetColumns, true) || !in_array($valueColumn, $targetColumns, true)) {
      continue;
    }
    $values = [];
    foreach ($rows as $row) {
      if (array_key_exists($sourceColumn, $row) && $row[$sourceColumn] !== null) {
        $values[(string)$row[$sourceColumn]] = $row[$sourceColumn];
      }
    }
    if (!$values) {
      $maps[$sourceColumn] = [];
      continue;
    }
    $quoted = [];
    foreach ($values as $value) {
      $quoted[] = qs($db, $value);
    }
    $lookup = db_all(
      $db,
      'SELECT ' . qi($idColumn) . ' AS __ms_id, ' . qi($valueColumn) . ' AS __ms_value FROM ' . qi($targetTable) .
      ' WHERE ' . qi($idColumn) . ' IN (' . implode(', ', $quoted) . ')'
    );
    $map = [];
    foreach ($lookup as $targetRow) {
      $map[(string)($targetRow['__ms_id'] ?? '')] = $targetRow['__ms_value'] ?? null;
    }
    $maps[$sourceColumn] = $map;
  }
  return $maps;
}

function ms_render_image_value($value, array $rule): string {
  if ($value === null) {
    return render_value(null);
  }
  $baseUrl = (string)($rule['base_url'] ?? '');
  $width = max(16, min(1024, (int)($rule['width'] ?? 96)));
  $src = $baseUrl . (string)$value;
  return '<a href="' . h($src) . '" target="_blank" rel="noopener" title="' . h((string)$value) . '">' .
    '<img src="' . h($src) . '" alt="' . h((string)$value) . '" loading="lazy" decoding="async" width="' . $width . '" style="width:' . $width . 'px;max-width:' . $width . 'px;height:auto;max-height:' . $width . 'px;object-fit:contain">' .
    '</a>';
}

function ms_render_formatted_value($value, array $rule): string {
  if ($value === null) {
    return render_value(null);
  }
  $kind = (string)($rule['kind'] ?? '');
  if ($kind === 'date' || $kind === 'datetime') {
    $format = (string)($rule['format'] ?? ($kind === 'date' ? 'd-m-Y' : 'd-m-Y H:i:s'));
    $allowed = $kind === 'date'
      ? ['d-m-Y', 'd/m/Y', 'd.m.Y', 'j/n/Y', 'Y-m-d', 'Ymd', 'm/d/Y', 'm-d-Y', 'j M Y', 'j F Y', 'M j, Y', 'F j, Y', 'D, d M Y', 'l, j F Y']
      : ['d-m-Y H:i', 'd-m-Y H:i:s', 'd/m/Y H:i', 'd/m/Y H:i:s', 'd.m.Y H:i', 'd.m.Y H:i:s', 'j/n/Y H:i', 'Y-m-d H:i', 'Y-m-d H:i:s', 'Y-m-d\TH:i', 'Y-m-d\TH:i:s', 'm/d/Y H:i', 'm/d/Y H:i:s', 'm/d/Y h:i A', 'm/d/Y h:i:s A', 'd/m/Y h:i A', 'd/m/Y h:i:s A', 'j M Y H:i', 'j F Y H:i', 'M j, Y H:i', 'M j, Y h:i A', 'F j, Y H:i', 'F j, Y h:i A', 'D, d M Y H:i', 'l, j F Y H:i'];
    if (!in_array($format, $allowed, true)) {
      return render_value($value);
    }
    try {
      $date = new DateTimeImmutable((string)$value);
      return '<span class="text-nowrap">' . h($date->format($format)) . '</span>';
    } catch (Throwable $e) {
      return render_value($value);
    }
  }
  if ($kind === 'money') {
    $text = trim((string)$value);
    if ($text === '' || !is_numeric($text)) {
      return render_value($value);
    }
    $decimals = max(0, min(4, (int)($rule['decimals'] ?? 2)));
    $currency = (string)($rule['currency'] ?? '');
    $symbols = ['' => '', 'EUR' => '€', 'USD' => '$', 'THB' => '฿', 'GBP' => '£'];
    $symbol = $symbols[$currency] ?? '';
    $formatted = number_format((float)$text, $decimals, '.', ',');
    return '<span class="text-nowrap">' . ($symbol !== '' ? h($symbol) . '&nbsp;' : '') . h($formatted) . '</span>';
  }
  return render_value($value);
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
  if ($includeName && $name === '') {
    throw new RuntimeException('Column name is required.');
  }

  $length = trim((string)($source['length'] ?? ''));
  $sql = $includeName ? qi($name) . ' ' : '';
  $sql .= $type;

  // Only emit a type parameter when that datatype actually supports one.
  // This deliberately ignores stale UI lengths for types such as FLOAT, INT,
  // DATE, TEXT and BLOB instead of producing invalid SQL such as FLOAT(255).
  if (in_array($type, ['ENUM', 'SET'], true)) {
    $values = preg_split('/\r\n|\r|\n/', $length);
    $values = array_values(array_filter(array_map('trim', is_array($values) ? $values : []), 'strlen'));
    if (!$values) {
      throw new RuntimeException($type . ' requires at least one value, one per line.');
    }
    $sql .= '(' . implode(', ', array_map(static function ($v) use ($db) { return qs($db, $v); }, $values)) . ')';
  } elseif (in_array($type, ['VARCHAR', 'VARBINARY'], true)) {
    if (preg_match('/^[1-9][0-9]*$/', $length) !== 1) {
      throw new RuntimeException($type . ' requires a positive length.');
    }
    $sql .= '(' . $length . ')';
  } elseif (in_array($type, ['CHAR', 'BINARY'], true)) {
    if ($length !== '') {
      if (preg_match('/^[1-9][0-9]*$/', $length) !== 1) {
        throw new RuntimeException($type . ' length must be a positive integer.');
      }
      $sql .= '(' . $length . ')';
    }
  } elseif (in_array($type, ['DECIMAL', 'DEC', 'NUMERIC', 'FIXED'], true)) {
    if ($length !== '') {
      if (preg_match('/^([0-9]+)(?:\s*,\s*([0-9]+))?$/', $length, $match) !== 1) {
        throw new RuntimeException($type . ' precision must be written as M or M,D.');
      }
      $precision = (int)$match[1];
      $scale = isset($match[2]) && $match[2] !== '' ? (int)$match[2] : null;
      if ($precision < 1 || $precision > 65) {
        throw new RuntimeException($type . ' precision must be between 1 and 65.');
      }
      if ($scale !== null && ($scale < 0 || $scale > 30 || $scale > $precision)) {
        throw new RuntimeException($type . ' scale must be between 0 and 30 and cannot exceed the precision.');
      }
      $sql .= '(' . $precision . ($scale !== null ? ',' . $scale : '') . ')';
    }
  } elseif ($type === 'BIT') {
    if ($length !== '') {
      if (ctype_digit($length) !== true || (int)$length < 1 || (int)$length > 64) {
        throw new RuntimeException('BIT length must be between 1 and 64.');
      }
      $sql .= '(' . (int)$length . ')';
    }
  } elseif (in_array($type, ['DATETIME', 'TIMESTAMP', 'TIME'], true)) {
    if ($length !== '') {
      if (ctype_digit($length) !== true || (int)$length < 0 || (int)$length > 6) {
        throw new RuntimeException($type . ' fractional-second precision must be between 0 and 6.');
      }
      $sql .= '(' . (int)$length . ')';
    }
  } elseif ($type === 'VECTOR') {
    if (preg_match('/^[1-9][0-9]*$/', $length) !== 1) {
      throw new RuntimeException('VECTOR requires a positive dimension in Length.');
    }
    $sql .= '(' . $length . ')';
  }

  $integerTypes = ['TINYINT', 'SMALLINT', 'MEDIUMINT', 'INT', 'INTEGER', 'BIGINT'];
  $unsignedTypes = array_merge($integerTypes, ['DECIMAL', 'DEC', 'NUMERIC', 'FIXED', 'FLOAT', 'DOUBLE', 'DOUBLE PRECISION', 'REAL']);
  if (!empty($source['unsigned']) && in_array($type, $unsignedTypes, true)) {
    $sql .= ' UNSIGNED';
  }

  $characterTypes = ['CHAR', 'VARCHAR', 'TINYTEXT', 'TEXT', 'MEDIUMTEXT', 'LONGTEXT', 'ENUM', 'SET'];
  if (in_array($type, $characterTypes, true)) {
    $charset = trim((string)($source['charset'] ?? ''));
    $collation = trim((string)($source['collation'] ?? ''));
    if ($charset !== '') {
      if (preg_match('/^[a-zA-Z0-9_]+$/', $charset) !== 1) {
        throw new RuntimeException('Invalid character set name.');
      }
      $sql .= ' CHARACTER SET ' . $charset;
    }
    if ($collation !== '') {
      if (preg_match('/^[a-zA-Z0-9_]+$/', $collation) !== 1) {
        throw new RuntimeException('Invalid collation name.');
      }
      $sql .= ' COLLATE ' . $collation;
    }
  }

  $generated = trim((string)($source['generated'] ?? ''));
  $autoIncrement = !empty($source['auto_increment']);
  if ($generated !== '') {
    if ($autoIncrement) {
      throw new RuntimeException('A generated column cannot also be AUTO_INCREMENT.');
    }
    $sql .= ' GENERATED ALWAYS AS (' . $generated . ') ' . (!empty($source['stored']) ? 'STORED' : 'VIRTUAL');
  } else {
    if ($autoIncrement && !in_array($type, $integerTypes, true)) {
      throw new RuntimeException('AUTO_INCREMENT is only allowed here for integer column types.');
    }

    // AUTO_INCREMENT columns are always NOT NULL. This also prevents a checked
    // Nullable box from generating a contradictory definition.
    $sql .= ($autoIncrement || empty($source['nullable'])) ? ' NOT NULL' : ' NULL';

    if (!empty($source['default_set'])) {
      if ($autoIncrement) {
        throw new RuntimeException('AUTO_INCREMENT columns cannot have an explicit default value.');
      }
      $default = (string)($source['default'] ?? '');
      if (!empty($source['default_expression'])) {
        if (trim($default) === '') {
          throw new RuntimeException('Default expression cannot be empty.');
        }
        $sql .= ' DEFAULT ' . $default;
      } else {
        $sql .= ' DEFAULT ' . qs($db, $default);
      }
    }
    if ($autoIncrement) {
      $sql .= ' AUTO_INCREMENT';
    }
    if (!empty($source['on_update'])) {
      if (!in_array($type, ['TIMESTAMP', 'DATETIME'], true)) {
        throw new RuntimeException('ON UPDATE CURRENT_TIMESTAMP is only valid for TIMESTAMP or DATETIME columns.');
      }
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


function ms_unsigned_decimal_compare(string $a, string $b): int {
  $a = ltrim($a, '0');
  $b = ltrim($b, '0');
  $a = $a === '' ? '0' : $a;
  $b = $b === '' ? '0' : $b;
  if (strlen($a) !== strlen($b)) {
    return strlen($a) < strlen($b) ? -1 : 1;
  }
  return strcmp($a, $b) <=> 0;
}

function ms_integer_bounds(array $column): ?array {
  $type = strtolower((string)($column['DATA_TYPE'] ?? ''));
  $unsigned = stripos((string)($column['COLUMN_TYPE'] ?? ''), 'unsigned') !== false;
  $bounds = [
    'tinyint' => ['-128', '127', '255'],
    'smallint' => ['-32768', '32767', '65535'],
    'mediumint' => ['-8388608', '8388607', '16777215'],
    'int' => ['-2147483648', '2147483647', '4294967295'],
    'integer' => ['-2147483648', '2147483647', '4294967295'],
    'bigint' => ['-9223372036854775808', '9223372036854775807', '18446744073709551615']
  ];
  if (!isset($bounds[$type])) {
    return null;
  }
  return $unsigned
    ? ['min' => '0', 'max' => $bounds[$type][2], 'unsigned' => true]
    : ['min' => $bounds[$type][0], 'max' => $bounds[$type][1], 'unsigned' => false];
}

function ms_normalize_integer_literal(array $column, string $value): string {
  $value = trim($value);
  if ($value === '') {
    return '';
  }
  $bounds = ms_integer_bounds($column);
  if ($bounds === null) {
    return $value;
  }
  if (preg_match('/^-?\d+$/', $value) !== 1) {
    throw new RuntimeException((string)$column['COLUMN_NAME'] . ' must contain an integer value.');
  }
  $negative = $value[0] === '-';
  if ($negative && !empty($bounds['unsigned'])) {
    throw new RuntimeException((string)$column['COLUMN_NAME'] . ' is UNSIGNED and cannot be negative.');
  }
  $digits = $negative ? substr($value, 1) : $value;
  $digits = ltrim($digits, '0');
  $digits = $digits === '' ? '0' : $digits;
  if ($digits === '0') {
    $negative = false;
  }
  $canonical = ($negative ? '-' : '') . $digits;

  if ($negative) {
    $minAbs = ltrim((string)$bounds['min'], '-');
    if (ms_unsigned_decimal_compare($digits, $minAbs) > 0) {
      throw new RuntimeException((string)$column['COLUMN_NAME'] . ' is below the minimum ' . $bounds['min'] . '.');
    }
  } elseif (ms_unsigned_decimal_compare($digits, (string)$bounds['max']) > 0) {
    throw new RuntimeException((string)$column['COLUMN_NAME'] . ' is above the maximum ' . $bounds['max'] . '.');
  }
  return $canonical;
}

function ms_normalize_decimal_literal(array $column, string $value): string {
  $value = trim(str_replace(',', '.', $value));
  if ($value === '') {
    return '';
  }
  $unsigned = stripos((string)($column['COLUMN_TYPE'] ?? ''), 'unsigned') !== false;
  if ($unsigned && isset($value[0]) && $value[0] === '-') {
    throw new RuntimeException((string)$column['COLUMN_NAME'] . ' is UNSIGNED and cannot be negative.');
  }
  if (preg_match('/^(-?)(?:(\d+)(?:\.(\d*))?|\.(\d+))$/', $value, $match) !== 1) {
    throw new RuntimeException((string)$column['COLUMN_NAME'] . ' must contain a decimal number.');
  }
  $negative = ($match[1] ?? '') === '-';
  $integer = $match[2] ?? '';
  $fraction = array_key_exists(3, $match) && $match[3] !== '' ? $match[3] : ($match[4] ?? '');
  $hadDecimal = strpos($value, '.') !== false;
  $integer = ltrim($integer, '0');
  $integer = $integer === '' ? '0' : $integer;

  $precision = isset($column['NUMERIC_PRECISION']) ? (int)$column['NUMERIC_PRECISION'] : 0;
  $scale = isset($column['NUMERIC_SCALE']) ? (int)$column['NUMERIC_SCALE'] : 0;
  if ($precision > 0) {
    $maxIntegerDigits = max(0, $precision - $scale);
    $significantIntegerDigits = $integer === '0' ? 0 : strlen($integer);
    if ($significantIntegerDigits > $maxIntegerDigits) {
      throw new RuntimeException((string)$column['COLUMN_NAME'] . ' allows at most ' . $maxIntegerDigits . ' digit(s) before the decimal point.');
    }
    if (strlen($fraction) > $scale) {
      throw new RuntimeException((string)$column['COLUMN_NAME'] . ' allows at most ' . $scale . ' decimal place(s).');
    }
  }
  if ($integer === '0' && ($fraction === '' || preg_match('/^0+$/', $fraction) === 1)) {
    $negative = false;
  }
  return ($negative ? '-' : '') . $integer . ($hadDecimal ? '.' . $fraction : '');
}

function ms_normalize_float_literal(array $column, string $value): string {
  $value = trim(str_replace(',', '.', $value));
  if ($value === '') {
    return '';
  }
  $unsigned = stripos((string)($column['COLUMN_TYPE'] ?? ''), 'unsigned') !== false;
  if ($unsigned && isset($value[0]) && $value[0] === '-') {
    throw new RuntimeException((string)$column['COLUMN_NAME'] . ' is UNSIGNED and cannot be negative.');
  }
  if (preg_match('/^-?(?:(?:\d+(?:\.\d*)?)|(?:\.\d+))(?:[eE][+-]?\d+)?$/', $value) !== 1) {
    throw new RuntimeException((string)$column['COLUMN_NAME'] . ' must contain a valid floating-point number.');
  }
  $parts = preg_split('/([eE])/', $value, 2, PREG_SPLIT_DELIM_CAPTURE);
  $mantissa = $parts[0];
  $exponent = count($parts) === 3 ? $parts[1] . $parts[2] : '';
  $negative = isset($mantissa[0]) && $mantissa[0] === '-';
  if ($negative) {
    $mantissa = substr($mantissa, 1);
  }
  if (strpos($mantissa, '.') === 0) {
    $mantissa = '0' . $mantissa;
  }
  if (strpos($mantissa, '.') !== false) {
    [$integer, $fraction] = explode('.', $mantissa, 2);
    $integer = ltrim($integer, '0');
    $integer = $integer === '' ? '0' : $integer;
    $mantissa = $integer . '.' . $fraction;
  } else {
    $mantissa = ltrim($mantissa, '0');
    $mantissa = $mantissa === '' ? '0' : $mantissa;
  }
  $zeroMantissa = preg_match('/^0(?:\.0*)?$/', $mantissa) === 1;
  return (($negative && !$zeroMantissa) ? '-' : '') . $mantissa . $exponent;
}

function ms_normalize_column_literal(array $column, $rawValue): string {
  $value = is_scalar($rawValue) || $rawValue === null ? (string)$rawValue : '';
  $type = strtolower((string)($column['DATA_TYPE'] ?? ''));
  if (in_array($type, ['tinyint', 'smallint', 'mediumint', 'int', 'integer', 'bigint'], true)) {
    return ms_normalize_integer_literal($column, $value);
  }
  if (in_array($type, ['decimal', 'dec', 'numeric', 'fixed'], true)) {
    return ms_normalize_decimal_literal($column, $value);
  }
  if (in_array($type, ['float', 'double', 'real'], true)) {
    return ms_normalize_float_literal($column, $value);
  }
  if ($type === 'date' && $value !== '' && preg_match('/^\d{4}-\d{2}-\d{2}$/', trim($value)) !== 1) {
    throw new RuntimeException((string)$column['COLUMN_NAME'] . ' must use YYYY-MM-DD.');
  }
  if (in_array($type, ['datetime', 'timestamp'], true) && $value !== '') {
    $value = str_replace('T', ' ', trim($value));
    if (preg_match('/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d{1,6})?$/', $value) !== 1) {
      throw new RuntimeException((string)$column['COLUMN_NAME'] . ' must use YYYY-MM-DD HH:MM:SS.');
    }
    return $value;
  }
  if ($type === 'time' && $value !== '' && preg_match('/^-?\d{1,3}:\d{2}:\d{2}(?:\.\d{1,6})?$/', trim($value)) !== 1) {
    throw new RuntimeException((string)$column['COLUMN_NAME'] . ' must use HH:MM:SS.');
  }
  if ($type === 'year' && $value !== '' && preg_match('/^\d{1,4}$/', trim($value)) !== 1) {
    throw new RuntimeException((string)$column['COLUMN_NAME'] . ' must contain a year.');
  }
  if ($type === 'json' && trim($value) !== '') {
    json_decode($value, true);
    if (json_last_error() !== JSON_ERROR_NONE) {
      throw new RuntimeException((string)$column['COLUMN_NAME'] . ' contains invalid JSON: ' . json_last_error_msg() . '.');
    }
  }
  return $value;
}

function ms_column_edit_spec(array $column): array {
  $type = strtolower((string)($column['DATA_TYPE'] ?? ''));
  $columnType = strtolower((string)($column['COLUMN_TYPE'] ?? ''));
  $unsigned = strpos($columnType, 'unsigned') !== false;
  $spec = [
    'kind' => 'text',
    'inputmode' => 'text',
    'placeholder' => '',
    'help' => '',
    'maxlength' => 0,
    'unsigned' => $unsigned,
    'min' => '',
    'max' => '',
    'precision' => 0,
    'scale' => 0
  ];

  $bounds = ms_integer_bounds($column);
  if ($bounds !== null) {
    $spec['kind'] = 'integer';
    $spec['inputmode'] = $unsigned ? 'numeric' : 'text';
    $spec['min'] = $bounds['min'];
    $spec['max'] = $bounds['max'];
    $spec['help'] = ($unsigned ? 'Unsigned integer' : 'Signed integer') . ' · ' . $bounds['min'] . ' to ' . $bounds['max'] . ' · no leading zeros';
    return $spec;
  }
  if (in_array($type, ['decimal', 'dec', 'numeric', 'fixed'], true)) {
    $spec['kind'] = 'decimal';
    $spec['inputmode'] = 'decimal';
    $spec['precision'] = (int)($column['NUMERIC_PRECISION'] ?? 0);
    $spec['scale'] = (int)($column['NUMERIC_SCALE'] ?? 0);
    $spec['help'] = ($unsigned ? 'Unsigned ' : 'Signed ') . strtoupper($type);
    if ($spec['precision'] > 0) {
      $spec['help'] .= '(' . $spec['precision'] . ',' . $spec['scale'] . ')';
    }
    $spec['help'] .= ' · decimal separator .';
    return $spec;
  }
  if (in_array($type, ['float', 'double', 'real'], true)) {
    $spec['kind'] = 'float';
    $spec['inputmode'] = 'decimal';
    $spec['help'] = ($unsigned ? 'Unsigned ' : 'Signed ') . strtoupper($type) . ' · scientific notation supported';
    return $spec;
  }
  if ($type === 'date') {
    $spec['kind'] = 'date';
    $spec['inputmode'] = 'numeric';
    $spec['placeholder'] = 'YYYY-MM-DD';
    $spec['help'] = 'Date · YYYY-MM-DD';
    return $spec;
  }
  if (in_array($type, ['datetime', 'timestamp'], true)) {
    $spec['kind'] = 'datetime';
    $spec['inputmode'] = 'numeric';
    $spec['placeholder'] = 'YYYY-MM-DD HH:MM:SS';
    $spec['help'] = strtoupper($type) . ' · YYYY-MM-DD HH:MM:SS';
    return $spec;
  }
  if ($type === 'time') {
    $spec['kind'] = 'time';
    $spec['inputmode'] = 'numeric';
    $spec['placeholder'] = 'HH:MM:SS';
    $spec['help'] = 'TIME · HH:MM:SS · negative times are allowed';
    return $spec;
  }
  if ($type === 'year') {
    $spec['kind'] = 'year';
    $spec['inputmode'] = 'numeric';
    $spec['placeholder'] = 'YYYY';
    $spec['maxlength'] = 4;
    $spec['help'] = 'YEAR · digits only';
    return $spec;
  }
  if (in_array($type, ['char', 'varchar'], true)) {
    $spec['kind'] = 'text';
    $spec['maxlength'] = (int)($column['CHARACTER_MAXIMUM_LENGTH'] ?? 0);
    if ($spec['maxlength'] > 0) {
      $spec['help'] = 'Maximum ' . $spec['maxlength'] . ' character(s)';
    }
    return $spec;
  }
  if ($type === 'json') {
    $spec['kind'] = 'json';
    $spec['help'] = 'JSON syntax is checked before saving';
    return $spec;
  }
  return $spec;
}

function ms_smart_input_attributes(array $spec): string {
  $attributes = ' data-ms-smart-input data-ms-kind="' . h($spec['kind']) . '"';
  $attributes .= ' data-ms-unsigned="' . (!empty($spec['unsigned']) ? '1' : '0') . '"';
  if ($spec['min'] !== '') {
    $attributes .= ' data-ms-min="' . h($spec['min']) . '"';
  }
  if ($spec['max'] !== '') {
    $attributes .= ' data-ms-max="' . h($spec['max']) . '"';
  }
  if ((int)$spec['precision'] > 0) {
    $attributes .= ' data-ms-precision="' . h((string)$spec['precision']) . '" data-ms-scale="' . h((string)$spec['scale']) . '"';
  }
  if ($spec['inputmode'] !== '') {
    $attributes .= ' inputmode="' . h($spec['inputmode']) . '"';
  }
  if ((int)$spec['maxlength'] > 0) {
    $attributes .= ' maxlength="' . h((string)$spec['maxlength']) . '"';
  }
  if ($spec['placeholder'] !== '') {
    $attributes .= ' placeholder="' . h($spec['placeholder']) . '"';
  }
  $attributes .= ' autocomplete="off" spellcheck="false"';
  return $attributes;
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


function sql_statement_explainable(string $statement): bool {
  $clean = preg_replace('/\A(?:\s|--[^\r\n]*(?:\r\n|\r|\n|$)|\#[^\r\n]*(?:\r\n|\r|\n|$)|\/\*.*?\*\/)+/s', '', $statement);
  if (!is_string($clean)) {
    return false;
  }
  $clean = ltrim($clean);
  return preg_match('/\A(?:SELECT|UPDATE|DELETE|INSERT|REPLACE|WITH)\b/i', $clean) === 1;
}

function explain_sql(mysqli $db, string $sql, int $displayLimit = MS_SQL_ROWS_DEFAULT): array {
  $statements = split_sql_script($sql);
  if (!$statements) {
    throw new RuntimeException('No executable SQL statement found.');
  }
  $explainStatements = [];
  foreach ($statements as $statement) {
    if (!sql_statement_explainable($statement)) {
      $preview = preg_replace('/\s+/', ' ', trim($statement));
      $preview = is_string($preview) ? substr($preview, 0, 160) : '';
      throw new RuntimeException('EXPLAIN supports SELECT, UPDATE, DELETE, INSERT, REPLACE and WITH statements. Unsupported statement: ' . $preview);
    }
    $explainStatements[] = 'EXPLAIN ' . $statement;
  }
  return execute_sql($db, implode(";\n", $explainStatements), true, $displayLimit);
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
    $returnQuery = ms_decode_navigation(p('return_to'));
    session_regenerate_id(true);
    $_SESSION['ms_login'] = compact('host', 'port', 'user', 'password', 'socket');
    $_SESSION['ms_attempts'] = 0;
    $_SESSION['ms_csrf'] = bin2hex(random_bytes(32));
    if ($returnQuery) {
      $_SESSION['ms_pending_navigation'] = $returnQuery;
      if (!ms_navigation_requires_database($returnQuery) || selected_db() !== '') {
        unset($_SESSION['ms_pending_navigation']);
        ms_go_to_query($returnQuery, 'Connected successfully.');
      }
      ms_go_to_query(['page' => 'databases'], 'Connected successfully. Choose a database to continue the requested operation.', 'info');
    }
    ms_go_to_query(['page' => 'databases'], 'Connected successfully.');
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
    ms_profile_config_ensure();
    $db = connect_db(false);

    if (g('ajax') === 'profile_config') {
      header('Content-Type: application/json; charset=UTF-8');
      try {
        require_csrf();
        $configAction = p('action');
        if ($configAction === 'raw_db_view') {
          $settings = ms_profile_settings();
          $settings['rawDbView'] = p('enabled') === '1';
          ms_profile_update_settings($settings);
        } elseif ($configAction === 'schema_width') {
          $settings = ms_profile_settings();
          $width = (int)p('width', '3');
          if (!in_array($width, [2,3,4,6,12], true)) throw new RuntimeException('Invalid schema width.');
          $settings['schemaColumnWidth'] = $width;
          ms_profile_update_settings($settings);
        } elseif ($configAction === 'sidebar_visibility') {
          $database = selected_db();
          if ($database === '' || !$db->select_db($database)) throw new RuntimeException('Choose a database first.');
          $table = p('table');
          if ($table === '' || !table_exists($db, $table)) throw new RuntimeException('Table or view not found.');
          ms_profile_set_sidebar_visibility($database, $table, p('visible') === '1');
        } elseif ($configAction === 'save_table_order') {
          $database = selected_db();
          if ($database === '' || !$db->select_db($database)) throw new RuntimeException('Choose a database first.');
          $table = p('table');
          if ($table === '' || !table_exists($db, $table)) throw new RuntimeException('Table or view not found.');
          $columns = array_values(array_map('strval', array_column(table_columns($db, $table), 'COLUMN_NAME')));
          $order = json_decode(p('order_json'), true);
          if (!is_array($order)) throw new RuntimeException('Invalid column order.');
          ms_profile_set_table_order($database, $table, $order, $columns);
        } elseif ($configAction === 'save_table_widths') {
          $database = selected_db();
          if ($database === '' || !$db->select_db($database)) throw new RuntimeException('Choose a database first.');
          $table = p('table');
          if ($table === '' || !table_exists($db, $table)) throw new RuntimeException('Table or view not found.');
          $columns = array_values(array_map('strval', array_column(table_columns($db, $table), 'COLUMN_NAME')));
          $widths = json_decode(p('widths_json'), true);
          if (!is_array($widths)) throw new RuntimeException('Invalid column widths.');
          ms_profile_set_table_widths($database, $table, $widths, $columns);
        } elseif ($configAction === 'save_search') {
          $database = selected_db();
          if ($database === '' || !$db->select_db($database)) throw new RuntimeException('Choose a database first.');
          $table = p('table');
          if ($table === '' || !table_exists($db, $table)) throw new RuntimeException('Table or view not found.');
          $columns = array_values(array_map('strval', array_column(table_columns($db, $table), 'COLUMN_NAME')));
          $rawSearch = json_decode(p('search_json'), true);
          if (!is_array($rawSearch)) throw new RuntimeException('Invalid saved search.');
          $query = ms_saved_search_normalize($rawSearch, $columns);
          ms_profile_save_search($database, $table, p('name'), $query);
        } elseif ($configAction === 'delete_search') {
          $database = selected_db();
          if ($database === '' || !$db->select_db($database)) throw new RuntimeException('Choose a database first.');
          $table = p('table');
          if ($table === '' || !table_exists($db, $table)) throw new RuntimeException('Table or view not found.');
          ms_profile_delete_search($database, $table, p('name'));
        } elseif ($configAction === 'reset_profile') {
          ms_profile_reset_active();
        } else {
          throw new RuntimeException('Unknown profile configuration operation.');
        }
        echo json_encode(['ok' => true, 'profile' => ms_active_profile_name()], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
      } catch (Throwable $ajaxError) {
        http_response_code(400);
        echo json_encode(['ok' => false, 'error' => $ajaxError->getMessage()], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
      }
      exit;
    }

    if (g('ajax') === 'select_more') {
      header('Content-Type: application/json; charset=UTF-8');
      try {
        if (selected_db() === '' || !$db->select_db(selected_db())) {
          throw new RuntimeException('Choose a database first.');
        }
        $table = g('table');
        if ($table === '' || !table_exists($db, $table)) {
          throw new RuntimeException('Table or view not found.');
        }
        $columns = table_columns($db, $table);
        $meta = db_one($db, 'SELECT TABLE_TYPE FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=' . qs($db, $table));
        $editable = ($meta['TABLE_TYPE'] ?? '') === 'BASE TABLE';
        $offset = max(0, (int)g('offset', '0'));
        $count = max(1, min(5000, (int)g('count', (string)ms_profile_setting_int('selectRows', MS_ROWS_PER_PAGE, 1, 500))));
        [$sql,$countSql,$limit,$page,$where,$aggregated,$showAll] = build_select_query($db, $table, $columns, $offset, $count);
        if ($showAll) {
          throw new RuntimeException('Show more is not available while Show all rows is enabled.');
        }
        $rows = db_all($db, $sql);
        $totalRow = db_one($db, $countSql);
        $total = (int)($totalRow['n'] ?? 0);
        $emptyViewConfig = ['hidden'=>[],'images'=>[],'soft_fk'=>[],'formats'=>[],'labels'=>[]];
        $storedViewConfig = $aggregated ? $emptyViewConfig : ms_column_view_table_config(selected_db(), $table);
        $viewConfig = (!$aggregated && ms_raw_db_view()) ? $emptyViewConfig : $storedViewConfig;
        $hiddenColumns = is_array($viewConfig['hidden'] ?? null) ? $viewConfig['hidden'] : [];
        $imageColumns = is_array($viewConfig['images'] ?? null) ? $viewConfig['images'] : [];
        $softFkRules = is_array($viewConfig['soft_fk'] ?? null) ? $viewConfig['soft_fk'] : [];
        $formatRules = is_array($viewConfig['formats'] ?? null) ? $viewConfig['formats'] : [];
        $softFkMaps = $aggregated ? [] : ms_soft_fk_maps($db, $rows, $softFkRules);
        $relations = [];
        if (!$aggregated) {
          foreach (db_all($db, "SELECT COLUMN_NAME,REFERENCED_TABLE_NAME,REFERENCED_COLUMN_NAME FROM information_schema.KEY_COLUMN_USAGE WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=" . qs($db,$table) . " AND REFERENCED_TABLE_NAME IS NOT NULL") as $relation) {
            $relations[$relation['COLUMN_NAME']] = $relation;
          }
        }
        $returnQuery = ms_navigation_query($_GET);
        unset($returnQuery['offset'], $returnQuery['count'], $returnQuery['single_id']);
        if (!$returnQuery) {
          $returnQuery = ['page'=>'select','table'=>$table];
        }
        $returnToken = ms_encode_navigation($returnQuery);
        $html = ms_render_select_rows_html($db,$table,$columns,$rows,$editable,$aggregated,$hiddenColumns,$imageColumns,$softFkRules,$softFkMaps,$formatRules,$relations,$returnQuery,$returnToken);
        $nextOffset = $offset + count($rows);
        echo json_encode([
          'ok' => true,
          'html' => $html,
          'returned' => count($rows),
          'next_offset' => $nextOffset,
          'has_more' => $nextOffset < $total,
          'total' => $total
        ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
      } catch (Throwable $ajaxError) {
        http_response_code(400);
        echo json_encode(['ok'=>false,'error'=>$ajaxError->getMessage()], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
      }
      exit;
    }

    if (g('ajax') === 'soft_fk_columns') {
      header('Content-Type: application/json; charset=UTF-8');
      try {
        if (selected_db() === '' || !$db->select_db(selected_db())) {
          throw new RuntimeException('Choose a database first.');
        }
        $targetTable = g('table');
        if ($targetTable === '' || !table_exists($db, $targetTable)) {
          throw new RuntimeException('Table or view not found.');
        }
        $columnNames = array_values(array_map('strval', array_column(table_columns($db, $targetTable), 'COLUMN_NAME')));
        echo json_encode(['ok' => true, 'columns' => $columnNames], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
      } catch (Throwable $ajaxError) {
        http_response_code(400);
        echo json_encode(['ok' => false, 'error' => $ajaxError->getMessage()], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
      }
      exit;
    }

    if (g('download') === 'table_structure_sql') {
      if (selected_db() === '' || !$db->select_db(selected_db())) {
        throw new RuntimeException('Choose a database first.');
      }
      $table = g('table');
      if ($table === '' || !table_exists($db, $table)) {
        throw new RuntimeException('Table not found.');
      }
      $create = db_one($db, 'SHOW CREATE TABLE ' . qi($table));
      $statement = (string)($create['Create Table'] ?? '');
      if ($statement === '') {
        throw new RuntimeException('Unable to read the CREATE TABLE statement.');
      }
      download_headers($table . '.sql', 'application/sql; charset=UTF-8');
      echo "-- MySQL Studio table structure export\n";
      echo '-- Database: ' . str_replace(["\r", "\n"], ' ', selected_db()) . "\n";
      echo '-- Table: ' . str_replace(["\r", "\n"], ' ', $table) . "\n";
      echo '-- Generated: ' . gmdate('Y-m-d H:i:s') . " UTC\n\n";
      echo $statement . ";\n";
      exit;
    }

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
      } elseif ($format === 'xls') {
        throw new RuntimeException('XLS export is generated in the browser from the Export page.');
      } else {
        download_headers((selected_db() ?: 'database') . '-' . gmdate('Ymd-His') . '.sql', 'application/sql; charset=UTF-8');
        dump_database($db, $tables, g('structure', '1') === '1', g('data', '1') === '1', g('drop', '1') === '1');
      }
      exit;
    }

    if ($_SERVER['REQUEST_METHOD'] === 'POST' && p('action') !== '') {
      require_csrf();
      $action = p('action');

      if ($action === 'switch_profile') {
        ms_set_active_profile(p('profile'));
        go([], 'Profile changed to ' . ms_active_profile_name() . '.');
      }

      if ($action === 'create_profile') {
        ms_profile_create(p('profile_name'));
        go(['page' => 'settings'], 'Profile created: ' . ms_active_profile_name() . '.');
      }

      if ($action === 'rename_profile') {
        ms_profile_rename(p('profile_name'));
        go(['page' => 'settings'], 'Profile renamed to ' . ms_active_profile_name() . '.');
      }

      if ($action === 'delete_profile') {
        $deleted = ms_active_profile_name();
        ms_profile_delete_active();
        go(['page' => 'settings'], 'Profile ' . $deleted . ' deleted. Default is now active.');
      }

      if ($action === 'save_profile_settings') {
        $current = ms_profile_settings();
        $menuPost = isset($_POST['menu']) && is_array($_POST['menu']) ? $_POST['menu'] : [];
        $menu = [];
        foreach (array_keys(ms_profile_default_settings()['menu']) as $key) $menu[$key] = isset($menuPost[$key]);
        $settings = [
          'theme' => p('theme'),
          'density' => p('density'),
          'scheme' => p('scheme'),
          'sqlRows' => (int)p('sqlRows', '1000'),
          'selectRows' => (int)p('selectRows', '50'),
          'paginationPosition' => p('paginationPosition', 'bottom'),
          'truncateCells' => p('truncateCells') === '1',
          'rawDbView' => !empty($current['rawDbView']),
          'schemaColumnWidth' => (int)($current['schemaColumnWidth'] ?? 3),
          'menu' => $menu
        ];
        ms_profile_update_settings($settings);
        go([], 'Settings saved for profile ' . ms_active_profile_name() . '.');
      }

      if ($action === 'select_db') {
        $database = p('database');
        $allowed = array_column(db_all($db, 'SHOW DATABASES'), 'Database');
        if (!in_array($database, $allowed, true)) {
          throw new RuntimeException('Database is not available.');
        }
        $_SESSION['ms_db'] = $database;
        $pendingNavigation = isset($_SESSION['ms_pending_navigation']) && is_array($_SESSION['ms_pending_navigation'])
          ? ms_navigation_query($_SESSION['ms_pending_navigation'])
          : [];
        if ($pendingNavigation) {
          unset($_SESSION['ms_pending_navigation']);
          ms_go_to_query($pendingNavigation, 'Database selected. Continuing the requested operation.');
        }
        ms_go_to_query(['page' => 'database'], 'Database selected.');
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

      if (strpos($action, 'column_view_') === 0) {
        $database = selected_db();
        if ($database === '') {
          throw new RuntimeException('Choose a database first.');
        }
        $configTable = p('config_table');
        $configColumn = p('config_column');

        if (in_array($action, ['column_view_hide', 'column_view_image_save', 'column_view_soft_fk_save', 'column_view_display_save', 'column_view_display_clear'], true)) {
          if ($configTable === '' || !table_exists($db, $configTable)) {
            throw new RuntimeException('The source table no longer exists.');
          }
          $sourceColumns = array_column(table_columns($db, $configTable), 'COLUMN_NAME');
          if ($configColumn === '' || !in_array($configColumn, $sourceColumns, true)) {
            throw new RuntimeException('The source column no longer exists.');
          }
        }

        if ($action === 'column_view_hide') {
          ms_column_view_hide($database, $configTable, $configColumn, true);
          go([], 'Column ' . $configColumn . ' is now hidden while browsing ' . $configTable . '.');
        } elseif ($action === 'column_view_show') {
          ms_column_view_hide($database, $configTable, $configColumn, false);
          go([], 'Column ' . $configColumn . ' is visible again.');
        } elseif ($action === 'column_view_show_all') {
          ms_column_view_show_all($database);
          go([], 'All hidden columns in ' . $database . ' are visible again.');
        } elseif ($action === 'column_view_image_save') {
          $baseUrl = trim(p('image_base_url'));
          $width = max(16, min(1024, (int)p('image_width', '96')));
          if (!ms_safe_image_base_url($baseUrl)) {
            throw new RuntimeException('Enter an HTTP(S) URL or a relative URL beginning with /, ./ or ../.');
          }
          ms_column_view_set_image($database, $configTable, $configColumn, ['base_url' => $baseUrl, 'width' => $width]);
          go([], $configTable . '.' . $configColumn . ' will now be displayed as a lazy-loaded image.');
        } elseif ($action === 'column_view_image_remove') {
          ms_column_view_set_image($database, $configTable, $configColumn, null);
          go([], 'Image display removed from ' . $configTable . '.' . $configColumn . '.');
        } elseif ($action === 'column_view_soft_fk_save') {
          $targetTable = p('soft_fk_table');
          $idColumn = p('soft_fk_id_column');
          $valueColumn = p('soft_fk_value_column');
          if ($targetTable === '' || !table_exists($db, $targetTable)) {
            throw new RuntimeException('Choose a valid target table or view.');
          }
          $targetColumns = array_column(table_columns($db, $targetTable), 'COLUMN_NAME');
          if (!in_array($idColumn, $targetColumns, true) || !in_array($valueColumn, $targetColumns, true)) {
            throw new RuntimeException('Choose valid ID and display-value columns.');
          }
          ms_column_view_set_soft_fk($database, $configTable, $configColumn, [
            'table' => $targetTable,
            'id_column' => $idColumn,
            'value_column' => $valueColumn
          ]);
          go([], 'Soft foreign key configured for ' . $configTable . '.' . $configColumn . '.');
        } elseif ($action === 'column_view_soft_fk_remove') {
          ms_column_view_set_soft_fk($database, $configTable, $configColumn, null);
          go([], 'Soft foreign key removed from ' . $configTable . '.' . $configColumn . '.');
        } elseif ($action === 'column_view_display_clear') {
          ms_column_view_clear_display($database, $configTable, $configColumn);
          ms_column_view_set_label($database, $configTable, $configColumn, null);
          ms_column_view_hide($database, $configTable, $configColumn, false);
          go([], 'Display customization removed and ' . $configTable . '.' . $configColumn . ' is visible again.');
        } elseif ($action === 'column_view_display_save') {
          $displayLabel = trim(p('display_label'));
          $displayLabelLength = preg_match_all('/./us', $displayLabel, $displayLabelChars);
          if ($displayLabelLength === false || $displayLabelLength > 200) {
            throw new RuntimeException('The custom field name must be valid UTF-8 and 200 characters or fewer.');
          }
          ms_column_view_set_label($database, $configTable, $configColumn, $displayLabel !== '' ? $displayLabel : null);
          $hideColumn = p('hide_column') === '1';
          $style = p('display_style');
          if ($style === '' || $style === 'default') {
            ms_column_view_clear_display($database, $configTable, $configColumn);
            ms_column_view_hide($database, $configTable, $configColumn, $hideColumn);
            go([], $configTable . '.' . $configColumn . ' now uses the default display' . ($hideColumn ? ' and is hidden.' : '.'));
          } elseif ($style === 'date') {
            $format = p('date_format');
            if (!in_array($format, ['d-m-Y', 'd/m/Y', 'd.m.Y', 'j/n/Y', 'Y-m-d', 'Ymd', 'm/d/Y', 'm-d-Y', 'j M Y', 'j F Y', 'M j, Y', 'F j, Y', 'D, d M Y', 'l, j F Y'], true)) {
              throw new RuntimeException('Choose a valid date format.');
            }
            ms_column_view_set_format($database, $configTable, $configColumn, ['kind' => 'date', 'format' => $format]);
            ms_column_view_hide($database, $configTable, $configColumn, $hideColumn);
            go([], $configTable . '.' . $configColumn . ' date display saved' . ($hideColumn ? ' and column hidden.' : '.'));
          } elseif ($style === 'datetime') {
            $format = p('datetime_format');
            if (!in_array($format, ['d-m-Y H:i', 'd-m-Y H:i:s', 'd/m/Y H:i', 'd/m/Y H:i:s', 'd.m.Y H:i', 'd.m.Y H:i:s', 'j/n/Y H:i', 'Y-m-d H:i', 'Y-m-d H:i:s', 'Y-m-d\TH:i', 'Y-m-d\TH:i:s', 'm/d/Y H:i', 'm/d/Y H:i:s', 'm/d/Y h:i A', 'm/d/Y h:i:s A', 'd/m/Y h:i A', 'd/m/Y h:i:s A', 'j M Y H:i', 'j F Y H:i', 'M j, Y H:i', 'M j, Y h:i A', 'F j, Y H:i', 'F j, Y h:i A', 'D, d M Y H:i', 'l, j F Y H:i'], true)) {
              throw new RuntimeException('Choose a valid date/time format.');
            }
            ms_column_view_set_format($database, $configTable, $configColumn, ['kind' => 'datetime', 'format' => $format]);
            ms_column_view_hide($database, $configTable, $configColumn, $hideColumn);
            go([], $configTable . '.' . $configColumn . ' date/time display saved' . ($hideColumn ? ' and column hidden.' : '.'));
          } elseif ($style === 'money') {
            $currency = p('money_currency');
            if (!in_array($currency, ['', 'EUR', 'USD', 'THB', 'GBP'], true)) {
              throw new RuntimeException('Choose a valid currency.');
            }
            $decimals = max(0, min(4, (int)p('money_decimals', '2')));
            ms_column_view_set_format($database, $configTable, $configColumn, ['kind' => 'money', 'currency' => $currency, 'decimals' => $decimals]);
            ms_column_view_hide($database, $configTable, $configColumn, $hideColumn);
            go([], $configTable . '.' . $configColumn . ' money display saved' . ($hideColumn ? ' and column hidden.' : '.'));
          } elseif ($style === 'image') {
            $baseUrl = trim(p('image_base_url'));
            $width = max(16, min(1024, (int)p('image_width', '96')));
            if (!ms_safe_image_base_url($baseUrl)) {
              throw new RuntimeException('Enter an HTTP(S) URL or a relative URL beginning with /, ./ or ../.');
            }
            ms_column_view_set_image($database, $configTable, $configColumn, ['base_url' => $baseUrl, 'width' => $width]);
            ms_column_view_hide($database, $configTable, $configColumn, $hideColumn);
            go([], $configTable . '.' . $configColumn . ' image display saved' . ($hideColumn ? ' and column hidden.' : '.'));
          } elseif ($style === 'soft_fk') {
            $targetTable = p('soft_fk_table');
            $idColumn = p('soft_fk_id_column');
            $valueColumn = p('soft_fk_value_column');
            if ($targetTable === '' || !table_exists($db, $targetTable)) {
              throw new RuntimeException('Choose a valid target table or view.');
            }
            $targetColumns = array_column(table_columns($db, $targetTable), 'COLUMN_NAME');
            if (!in_array($idColumn, $targetColumns, true) || !in_array($valueColumn, $targetColumns, true)) {
              throw new RuntimeException('Choose valid ID and display-value columns.');
            }
            ms_column_view_set_soft_fk($database, $configTable, $configColumn, ['table' => $targetTable, 'id_column' => $idColumn, 'value_column' => $valueColumn]);
            ms_column_view_hide($database, $configTable, $configColumn, $hideColumn);
            go([], 'Virtual foreign key saved for ' . $configTable . '.' . $configColumn . ($hideColumn ? ' and column hidden.' : '.'));
          } else {
            throw new RuntimeException('Choose a valid display style.');
          }
        }
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
        $sqlDisplayLimit = max(1, min(100000, (int)p('row_limit', (string)ms_profile_setting_int('sqlRows', MS_SQL_ROWS_DEFAULT, 1, 100000))));
        if (p('sql_submit') === 'explain') {
          [$sqlResults, $sqlTime] = explain_sql($db, $sql, $sqlDisplayLimit);
          $sqlExplainMode = true;
        } else {
          [$sqlResults, $sqlTime] = execute_sql($db, $sql, p('show_all') === '1', $sqlDisplayLimit);
          $sqlExplainMode = false;
        }
        $_SESSION['ms_last_sql'] = $sql;
      } elseif ($action === 'create_table') {
        $name = trim(p('name'));
        $columns = isset($_POST['columns']) && is_array($_POST['columns']) ? $_POST['columns'] : [];
        if ($name === '' || !$columns) {
          throw new RuntimeException('A table name and at least one column are required.');
        }

        $definitions = [];
        $primaryColumns = [];
        $secondaryDefinitions = [];
        $seenColumnNames = [];
        $autoIncrementColumns = [];

        foreach ($columns as $column) {
          if (!is_array($column)) {
            continue;
          }
          $columnName = trim((string)($column['name'] ?? ''));
          if ($columnName === '') {
            continue;
          }
          $nameKey = strtolower($columnName);
          if (isset($seenColumnNames[$nameKey])) {
            throw new RuntimeException('Duplicate column name: ' . $columnName . '.');
          }
          $seenColumnNames[$nameKey] = true;

          $definitions[] = build_column_sql($db, $column);

          $key = strtoupper(trim((string)($column['index'] ?? '')));
          if (!in_array($key, ['', 'PRIMARY', 'INDEX', 'UNIQUE'], true)) {
            throw new RuntimeException('Invalid index type for column ' . $columnName . '.');
          }
          if (!empty($column['auto_increment'])) {
            $autoIncrementColumns[] = $columnName;
            // Never send an unindexed AUTO_INCREMENT to MySQL. If the user
            // explicitly turned the key selector off, create a normal index.
            if ($key === '') {
              $key = 'INDEX';
            }
          }

          if ($key === 'PRIMARY') {
            $primaryColumns[] = qi($columnName);
          } elseif ($key === 'UNIQUE') {
            $secondaryDefinitions[] = 'UNIQUE KEY (' . qi($columnName) . ')';
          } elseif ($key === 'INDEX') {
            $secondaryDefinitions[] = 'KEY (' . qi($columnName) . ')';
          }
        }

        if (!$definitions) {
          throw new RuntimeException('A table name and at least one named column are required.');
        }
        if (count($autoIncrementColumns) > 1) {
          throw new RuntimeException('MySQL permits only one AUTO_INCREMENT column per table.');
        }
        if ($primaryColumns) {
          $definitions[] = 'PRIMARY KEY (' . implode(', ', $primaryColumns) . ')';
        }
        $definitions = array_merge($definitions, $secondaryDefinitions);

        $engine = preg_match('/^[A-Za-z0-9_]+$/', p('engine')) ? p('engine') : 'InnoDB';
        $collation = preg_match('/^[A-Za-z0-9_]+$/', p('collation')) ? p('collation') : 'utf8mb4_unicode_ci';
        $sql = 'CREATE TABLE ' . qi($name) . ' (' . implode(', ', $definitions) . ') ENGINE=' . $engine . ' COLLATE=' . $collation;
        if (p('comment') !== '') {
          $sql .= ' COMMENT=' . qs($db, p('comment'));
        }
        if (!$db->query($sql)) {
          throw new RuntimeException('MySQL #' . $db->errno . ': ' . $db->error . ' | SQL: ' . $sql);
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
      } elseif ($action === 'reorder_column') {
        $table = g('table');
        if (!table_exists($db, $table)) {
          throw new RuntimeException('Table not found.');
        }
        $columnName = p('column');
        $after = p('after');
        $columns = table_columns($db, $table);
        $columnNames = array_map('strval', array_column($columns, 'COLUMN_NAME'));
        if (!in_array($columnName, $columnNames, true)) {
          throw new RuntimeException('Column not found.');
        }
        if ($after !== '' && !in_array($after, $columnNames, true)) {
          throw new RuntimeException('Invalid target column position.');
        }
        if ($after === $columnName) {
          throw new RuntimeException('A column cannot be positioned after itself.');
        }
        $currentIndex = array_search($columnName, $columnNames, true);
        $currentAfter = $currentIndex === 0 ? '' : (string)$columnNames[$currentIndex - 1];
        if ($after === $currentAfter) {
          go([], 'Column position unchanged.', 'info');
        }
        $definition = exact_column_definition($db, $table, $columnName);
        $sql = 'ALTER TABLE ' . qi($table) . ' MODIFY COLUMN ' . qi($columnName) . ' ' . $definition;
        $sql .= $after === '' ? ' FIRST' : ' AFTER ' . qi($after);
        if (!$db->query($sql)) {
          throw new RuntimeException($db->error);
        }
        go([], 'Column position updated.');
      } elseif ($action === 'quick_clone_column') {
        $table = g('table');
        if ($table === '' || !table_exists($db, $table)) {
          throw new RuntimeException('Table not found.');
        }
        $sourceName = p('column');
        $columns = table_columns($db, $table);
        $columnNames = array_map('strval', array_column($columns, 'COLUMN_NAME'));
        if ($sourceName === '' || !in_array($sourceName, $columnNames, true)) {
          throw new RuntimeException('Column not found.');
        }
        $cloneBaseName = $sourceName;
        $suffix = 1;
        if (preg_match('/^(.*)-(\d+)$/', $sourceName, $cloneNameMatch) === 1 && (string)$cloneNameMatch[1] !== '') {
          $cloneBaseName = (string)$cloneNameMatch[1];
          $suffix = max(1, (int)$cloneNameMatch[2] + 1);
        }
        do {
          $newName = $cloneBaseName . '-' . $suffix;
          $suffix++;
        } while (in_array($newName, $columnNames, true));
        $definition = exact_column_definition($db, $table, $sourceName);
        // A table can normally contain only one AUTO_INCREMENT column. Keep the
        // cloned field definition otherwise identical, but do not duplicate that attribute.
        $definition = preg_replace('/\s+AUTO_INCREMENT\b/i', '', $definition) ?? $definition;
        $sql = 'ALTER TABLE ' . qi($table) . ' ADD COLUMN ' . qi($newName) . ' ' . $definition . ' AFTER ' . qi($sourceName);
        if (!$db->query($sql)) {
          throw new RuntimeException($db->error);
        }
        go([], 'Column cloned as ' . $newName . '.');
      } elseif ($action === 'quick_rename_column') {
        $table = g('table');
        if ($table === '' || !table_exists($db, $table)) {
          throw new RuntimeException('Table not found.');
        }
        $oldName = p('column');
        $newName = trim(p('new_name'));
        $columns = table_columns($db, $table);
        $columnNames = array_map('strval', array_column($columns, 'COLUMN_NAME'));
        if ($oldName === '' || !in_array($oldName, $columnNames, true)) {
          throw new RuntimeException('Column not found.');
        }
        if ($newName === '') {
          throw new RuntimeException('The new column name cannot be empty.');
        }
        if ($newName === $oldName) {
          go([], 'Column name unchanged.', 'info');
        }
        if (in_array($newName, $columnNames, true)) {
          throw new RuntimeException('A column named ' . $newName . ' already exists.');
        }
        $definition = exact_column_definition($db, $table, $oldName);
        $sql = 'ALTER TABLE ' . qi($table) . ' CHANGE COLUMN ' . qi($oldName) . ' ' . qi($newName) . ' ' . $definition;
        if (!$db->query($sql)) {
          throw new RuntimeException($db->error);
        }
        go([], 'Column renamed to ' . $newName . '.');
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
        $cloneSourceIdentity = decode_identity(p('clone_source'));
        $cloneSourceRow = null;
        if (!is_array($identity) && is_array($cloneSourceIdentity)) {
          $cloneSourceRow = db_one($db, 'SELECT * FROM ' . qi($table) . ' WHERE ' . row_identity_where($db, $columns, $cloneSourceIdentity) . ' LIMIT 1');
        }
        $returnQuery = ms_decode_navigation(p('return_to'));
        if (($returnQuery['page'] ?? '') !== 'select' || ($returnQuery['table'] ?? '') !== $table) {
          $returnQuery = ['page' => 'select', 'table' => $table];
        }
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
          if (!is_array($identity) && is_array($cloneSourceRow) && isset($keepBlobs[$name]) && !$hasUpload) {
            $sourceValue = $cloneSourceRow[$name] ?? null;
            $assignments[$name] = $sourceValue === null ? 'NULL' : qs($db, $sourceValue);
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
            $literalValue = ms_normalize_column_literal($column, $input[$name] ?? '');
            $sqlValue = qs($db, $literalValue);
          }
          $assignments[$name] = $sqlValue;
        }
        if (is_array($identity)) {
          $set = [];
          foreach ($assignments as $name => $value) {
            $set[] = qi($name) . ' = ' . $value;
          }
          if (!$set) {
            ms_go_to_query($returnQuery, 'Nothing changed.', 'info');
          }
          $sql = 'UPDATE ' . qi($table) . ' SET ' . implode(', ', $set) . ' WHERE ' . row_identity_where($db, $columns, $identity) . ' LIMIT 1';
        } else {
          $sql = $assignments ? 'INSERT INTO ' . qi($table) . ' (' . implode(', ', array_map('qi', array_keys($assignments))) . ') VALUES (' . implode(', ', array_values($assignments)) . ')' : 'INSERT INTO ' . qi($table) . ' () VALUES ()';
        }
        if (!$db->query($sql)) {
          throw new RuntimeException($db->error);
        }
        ms_go_to_query($returnQuery, is_array($identity) ? 'Row updated.' : 'Row inserted.');
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
      } elseif ($action === 'delete_row') {
        $table = g('table');
        if (!table_exists($db, $table)) {
          throw new RuntimeException('Table not found.');
        }
        $columns = table_columns($db, $table);
        $identity = decode_identity(g('single_id', p('single_id')));
        if (!is_array($identity)) {
          throw new RuntimeException('Invalid row identity.');
        }
        $returnQuery = ms_decode_navigation(p('return_to'));
        if (($returnQuery['page'] ?? '') !== 'select' || ($returnQuery['table'] ?? '') !== $table) {
          $returnQuery = ['page' => 'select', 'table' => $table];
        }
        $sql = 'DELETE FROM ' . qi($table) . ' WHERE ' . row_identity_where($db, $columns, $identity) . ' LIMIT 1';
        if (!$db->query($sql)) {
          throw new RuntimeException($db->error);
        }
        ms_go_to_query($returnQuery, $db->affected_rows === 1 ? 'Row deleted.' : 'The row was not found.', $db->affected_rows === 1 ? 'success' : 'warning');
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
  $clientSettings = ms_profile_settings();
  $clientSettings['hiddenSidebarObjects'] = selected_db() !== '' ? ms_profile_hidden_sidebar(selected_db()) : [];
  $clientSettingsJson = json_encode($clientSettings, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) ?: '{}';
  $defaultSettingsJson = json_encode(ms_profile_default_settings(), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) ?: '{}';
  $csrfJson = json_encode((string)($_SESSION['ms_csrf'] ?? ''), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) ?: '""';
  ?><!doctype html>
<html lang="en" data-bs-theme="light" data-density="standard" data-scheme="ocean" data-raw-db-view="<?= ms_raw_db_view() ? 'true' : 'false' ?>">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title><?= h($title) ?> · <?= h(MS_APP_NAME) ?></title>
  <script>
    (() => {
      'use strict';
      const menuKeys = ['databases','database','sql','export','schema','views','routines','triggers','events','processes','users','variables'];
      const defaults = <?= $defaultSettingsJson ?>;
      const serverSettings = <?= $clientSettingsJson ?>;
      const csrf = <?= $csrfJson ?>;
      window.msSettingsMeta = {menuKeys,defaults};
      window.msLoadSettings = () => JSON.parse(JSON.stringify(serverSettings));
      window.msConfigPost = async (action, data = {}) => {
        const body = new URLSearchParams();
        body.set('csrf', csrf);
        body.set('action', action);
        Object.entries(data).forEach(([key,value]) => body.set(key, value == null ? '' : String(value)));
        const response = await fetch('?ajax=profile_config', {
          method: 'POST',
          credentials: 'same-origin',
          headers: {'Content-Type':'application/x-www-form-urlencoded;charset=UTF-8'},
          body: body.toString()
        });
        let payload = null;
        try { payload = await response.json(); } catch (error) {}
        if (!response.ok || !payload || payload.ok !== true) {
          throw new Error(payload && payload.error ? payload.error : 'Unable to save profile configuration.');
        }
        return payload;
      };
      window.msApplySettings = settings => {
        const root = document.documentElement;
        root.setAttribute('data-bs-theme', settings.theme);
        root.setAttribute('data-density', settings.density);
        root.setAttribute('data-scheme', settings.scheme);
        root.setAttribute('data-truncate-cells', settings.truncateCells ? 'true' : 'false');
        root.setAttribute('data-pagination-position', settings.paginationPosition);
        document.querySelectorAll('[data-ms-menu]').forEach(item => {
          item.hidden = settings.menu && settings.menu[item.dataset.msMenu] === false;
        });
        const hiddenSidebarObjects = settings.hiddenSidebarObjects && typeof settings.hiddenSidebarObjects === 'object' && !Array.isArray(settings.hiddenSidebarObjects) ? settings.hiddenSidebarObjects : {};
        const rawDbView = root.getAttribute('data-raw-db-view') === 'true';
        document.querySelectorAll('[data-ms-sidebar-object-key]').forEach(item => {
          item.hidden = rawDbView ? false : hiddenSidebarObjects[item.dataset.msSidebarObjectKey] === true;
        });
        document.querySelectorAll('[data-ms-sql-row-limit]').forEach(input => input.value = settings.sqlRows);
        document.querySelectorAll('[data-ms-sql-limit-label]').forEach(label => label.textContent = Number(settings.sqlRows || 0).toLocaleString());
      };
      window.msApplySettings(serverSettings);
    })();
  </script>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.8/dist/css/bootstrap.min.css" rel="stylesheet">
  <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/7.0.1/css/all.min.css" rel="stylesheet">
  <style>
    :root{--sidebar:260px;--ms-accent:#0d6efd;--ms-accent-hover:#0b5ed7;--ms-accent-rgb:13,110,253;--ms-accent-text:#fff;--ms-link:#0a58ca;--ms-table-font-size:14px;--ms-table-line-height:1.3;--ms-table-pad-y:.42rem;--ms-table-pad-x:.55rem;--ms-cell-max-width:420px;--ms-cell-max-height:9rem;--ms-sql-editor-font-size:.9rem;--ms-sql-editor-min-height:220px}
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
    body{min-height:100vh}.sidebar{width:var(--sidebar);position:fixed;inset:0 auto 0 0;overflow:auto;background:var(--bs-tertiary-bg);border-right:1px solid var(--bs-border-color)}.main{margin-left:var(--sidebar);padding:1.25rem}.brand{font-weight:700;letter-spacing:.02em}.ms-raw-db-switch{margin-top:.45rem;padding:.38rem .5rem;border:1px solid var(--bs-border-color);border-radius:.55rem;background:var(--bs-body-bg)}.ms-raw-db-switch .form-check{min-height:0}.ms-raw-db-switch .form-check-input{cursor:pointer}.ms-raw-db-switch .form-check-label{cursor:pointer;line-height:1.15}.ms-raw-db-switch.is-active{border-color:var(--bs-warning);background:var(--bs-warning-bg-subtle)}.table{font-size:var(--ms-table-font-size);line-height:var(--ms-table-line-height)}.table>:not(caption)>*>*{padding:var(--ms-table-pad-y) var(--ms-table-pad-x)}.table-scroll{overflow:auto;max-height:70vh}.table-scroll th{position:sticky;top:0;z-index:2;background:var(--bs-body-bg)}.ms-layout-table th[data-ms-column]{user-select:none;padding-right:calc(var(--ms-table-pad-x) + .8rem)!important;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.ms-col-header-main{display:inline-flex;align-items:center;max-width:calc(100% - .15rem);min-width:0;white-space:nowrap;vertical-align:middle}.ms-col-header-name{display:block;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;cursor:pointer}.ms-col-header-name:hover,.ms-col-header-name:focus{color:var(--ms-accent);text-decoration:underline}.ms-col-drag-handle{display:inline-flex;flex:0 0 auto;align-items:center;justify-content:center;margin-right:.35rem;padding:0 .1rem;color:var(--bs-secondary-color);cursor:grab;opacity:.45;vertical-align:middle;touch-action:none}.ms-layout-table th[data-ms-column]:hover .ms-col-drag-handle,.ms-col-drag-handle:focus{opacity:1}.ms-col-drag-handle:active{cursor:grabbing}.ms-layout-table th.ms-column-dragging{opacity:.45}.ms-layout-table th.ms-column-drop-before{box-shadow:inset 3px 0 0 var(--ms-accent)}.ms-layout-table th.ms-column-drop-after{box-shadow:inset -3px 0 0 var(--ms-accent)}.ms-col-resizer{position:absolute;top:0;right:-3px;bottom:0;width:8px;cursor:col-resize;z-index:4;touch-action:none}.ms-col-resizer::after{content:"";position:absolute;top:20%;bottom:20%;left:3px;border-left:1px solid var(--bs-border-color)}body.ms-column-resizing{cursor:col-resize!important;user-select:none!important}.cell-value{display:inline-block;max-width:var(--ms-cell-max-width);max-height:var(--ms-cell-max-height);overflow:auto;white-space:pre-wrap;line-height:inherit}.ms-data-table>thead>tr>th{font-size:inherit;line-height:inherit}.ms-data-table>tbody>tr>td{font-size:inherit;line-height:inherit}.ms-row-actions-cell{width:1%;white-space:nowrap}.ms-row-actions{display:inline-flex;align-items:center;gap:.16rem;white-space:nowrap}.ms-row-action{display:inline-flex;align-items:center;justify-content:center;border:0;background:transparent;color:var(--bs-secondary-color);padding:.08rem .14rem;line-height:1;text-decoration:none;border-radius:.2rem;cursor:pointer}.ms-row-action:hover,.ms-row-action:focus{color:var(--ms-accent);background:var(--bs-tertiary-bg)}.ms-row-action.ms-row-delete{color:var(--bs-danger)}.ms-row-action.ms-row-delete:hover,.ms-row-action.ms-row-delete:focus{color:var(--bs-danger);background:var(--bs-danger-bg-subtle)}html[data-truncate-cells="true"] .ms-layout-table tbody td[data-ms-column]{max-width:320px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}html[data-truncate-cells="true"] .ms-layout-table tbody td[data-ms-column] .cell-value{display:block;max-width:100%;max-height:none;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}html[data-truncate-cells="true"] .ms-layout-table tbody td[data-ms-column] .cell-value br{display:none}.sql-editor{font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace;font-size:var(--ms-sql-editor-font-size);min-height:var(--ms-sql-editor-min-height);tab-size:2}.code{font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace;white-space:pre-wrap}.schema-canvas{position:relative;min-height:650px;background-image:radial-gradient(var(--bs-border-color) 1px,transparent 1px);background-size:20px 20px}.schema-table{position:relative;display:inline-block;vertical-align:top;width:240px;margin:12px}.schema-grid>.schema-col .schema-table{display:block;width:100%;margin:0}.schema-grid>.schema-col{min-width:0}.schema-width-picker .btn{white-space:nowrap}.schema-line{color:var(--ms-accent)}.nav-link.active{font-weight:600}.danger-zone{border:1px solid var(--bs-danger-border-subtle);background:var(--bs-danger-bg-subtle)}.ms-sidebar-object-row{display:flex;align-items:center;gap:.2rem;padding:.08rem .12rem;border-bottom:1px solid rgba(var(--bs-secondary-rgb),.08)}.ms-sidebar-object-row:last-child{border-bottom:0}.ms-sidebar-object-name{display:flex;align-items:center;min-width:0;flex:1;padding:.18rem .2rem;color:var(--bs-body-color);text-decoration:none;border-radius:.25rem}.ms-sidebar-object-name:hover,.ms-sidebar-object-name:focus{color:var(--ms-accent);background:var(--bs-tertiary-bg)}.ms-sidebar-object-actions{display:inline-flex;flex:0 0 auto;align-items:center;gap:.05rem}.ms-sidebar-object-action{display:inline-flex;align-items:center;justify-content:center;width:1.55rem;height:1.55rem;border-radius:.25rem;color:var(--bs-secondary-color);text-decoration:none}.ms-sidebar-object-action:hover,.ms-sidebar-object-action:focus{color:var(--ms-accent);background:var(--bs-tertiary-bg)}
    a{color:var(--ms-link)}.text-primary{color:var(--ms-accent)!important}.bg-primary{background-color:var(--ms-accent)!important}.border-primary{border-color:var(--ms-accent)!important}.nav-pills{--bs-nav-pills-link-active-bg:var(--ms-accent)}.page-link{color:var(--ms-link)}.active>.page-link,.page-link.active{background-color:var(--ms-accent);border-color:var(--ms-accent);color:var(--ms-accent-text)}.form-check-input:checked{background-color:var(--ms-accent);border-color:var(--ms-accent)}.form-control:focus,.form-select:focus,.form-check-input:focus{border-color:rgba(var(--ms-accent-rgb),.65);box-shadow:0 0 0 .25rem rgba(var(--ms-accent-rgb),.2)}
    .btn-primary{--bs-btn-color:var(--ms-accent-text);--bs-btn-bg:var(--ms-accent);--bs-btn-border-color:var(--ms-accent);--bs-btn-hover-color:var(--ms-accent-text);--bs-btn-hover-bg:var(--ms-accent-hover);--bs-btn-hover-border-color:var(--ms-accent-hover);--bs-btn-active-color:var(--ms-accent-text);--bs-btn-active-bg:var(--ms-accent-hover);--bs-btn-active-border-color:var(--ms-accent-hover);--bs-btn-disabled-color:var(--ms-accent-text);--bs-btn-disabled-bg:var(--ms-accent);--bs-btn-disabled-border-color:var(--ms-accent)}
    html[data-density="ultracompact"]{--sidebar:205px;--ms-table-font-size:14px;--ms-table-line-height:1.02;--ms-table-pad-y:.035rem;--ms-table-pad-x:.16rem;--ms-cell-max-width:260px;--ms-cell-max-height:4.5rem;--ms-sql-editor-font-size:.9rem;--ms-sql-editor-min-height:120px}html[data-density="ultracompact"] .main{padding:.22rem}html[data-density="ultracompact"] .sidebar{padding:.22rem!important}html[data-density="ultracompact"] .form-control,html[data-density="ultracompact"] .form-select,html[data-density="ultracompact"] .btn{font-size:inherit;padding:.06rem .22rem;min-height:0;line-height:1.15}html[data-density="ultracompact"] .card-body,html[data-density="ultracompact"] .card-header,html[data-density="ultracompact"] .card-footer{padding:.18rem .28rem}html[data-density="ultracompact"] .nav-link,html[data-density="ultracompact"] .list-group-item{padding:.08rem .18rem}html[data-density="ultracompact"] .mb-4{margin-bottom:.22rem!important}html[data-density="ultracompact"] .mb-3{margin-bottom:.16rem!important}html[data-density="ultracompact"] .mb-2{margin-bottom:.1rem!important}html[data-density="ultracompact"] .mb-1{margin-bottom:.06rem!important}html[data-density="ultracompact"] .mt-3{margin-top:.16rem!important}html[data-density="ultracompact"] .mt-2{margin-top:.1rem!important}html[data-density="ultracompact"] .mt-1{margin-top:.06rem!important}html[data-density="ultracompact"] .p-3{padding:.22rem!important}html[data-density="ultracompact"] .p-2{padding:.14rem!important}html[data-density="ultracompact"] .py-3{padding-top:.22rem!important;padding-bottom:.22rem!important}html[data-density="ultracompact"] .py-2{padding-top:.14rem!important;padding-bottom:.14rem!important}html[data-density="ultracompact"] .px-3{padding-left:.22rem!important;padding-right:.22rem!important}html[data-density="ultracompact"] .px-2{padding-left:.14rem!important;padding-right:.14rem!important}html[data-density="ultracompact"] .gap-3{gap:.22rem!important}html[data-density="ultracompact"] .gap-2{gap:.14rem!important}html[data-density="ultracompact"] .g-3{--bs-gutter-x:.22rem;--bs-gutter-y:.22rem}html[data-density="ultracompact"] .g-2{--bs-gutter-x:.14rem;--bs-gutter-y:.14rem}html[data-density="ultracompact"] hr{margin:.22rem 0}html[data-density="ultracompact"] .alert{padding:.18rem .28rem;margin-bottom:.18rem}html[data-density="ultracompact"] .badge{padding:.15em .28em}html[data-density="ultracompact"] .pagination{margin-bottom:.12rem}html[data-density="ultracompact"] .page-link{padding:.08rem .22rem}html[data-density="ultracompact"] h1,html[data-density="ultracompact"] h2,html[data-density="ultracompact"] h3,html[data-density="ultracompact"] h4,html[data-density="ultracompact"] h5,html[data-density="ultracompact"] h6{margin-bottom:.08rem}
    html[data-density="compact"]{--sidebar:225px;--ms-table-font-size:14px;--ms-table-line-height:1.1;--ms-table-pad-y:.11rem;--ms-table-pad-x:.28rem;--ms-cell-max-width:340px;--ms-cell-max-height:6.5rem;--ms-sql-editor-font-size:.9rem;--ms-sql-editor-min-height:160px}html[data-density="compact"] .main{padding:.48rem}html[data-density="compact"] .sidebar{padding:.42rem!important}html[data-density="compact"] .form-control,html[data-density="compact"] .form-select,html[data-density="compact"] .btn{font-size:inherit;padding:.16rem .35rem;min-height:0;line-height:1.2}html[data-density="compact"] .card-body,html[data-density="compact"] .card-header,html[data-density="compact"] .card-footer{padding:.38rem .5rem}html[data-density="compact"] .nav-link,html[data-density="compact"] .list-group-item{padding:.18rem .32rem}html[data-density="compact"] .mb-4{margin-bottom:.48rem!important}html[data-density="compact"] .mb-3{margin-bottom:.34rem!important}html[data-density="compact"] .mb-2{margin-bottom:.24rem!important}html[data-density="compact"] .mt-3{margin-top:.34rem!important}html[data-density="compact"] .mt-2{margin-top:.24rem!important}html[data-density="compact"] .p-3{padding:.48rem!important}html[data-density="compact"] .p-2{padding:.32rem!important}html[data-density="compact"] .py-3{padding-top:.48rem!important;padding-bottom:.48rem!important}html[data-density="compact"] .py-2{padding-top:.32rem!important;padding-bottom:.32rem!important}html[data-density="compact"] .gap-3{gap:.48rem!important}html[data-density="compact"] .gap-2{gap:.32rem!important}html[data-density="compact"] .g-3{--bs-gutter-x:.48rem;--bs-gutter-y:.48rem}html[data-density="compact"] .g-2{--bs-gutter-x:.32rem;--bs-gutter-y:.32rem}html[data-density="compact"] hr{margin:.48rem 0}html[data-density="compact"] .alert{padding:.38rem .5rem;margin-bottom:.38rem}html[data-density="compact"] .page-link{padding:.16rem .35rem}
    html[data-density="standard"]{--ms-table-font-size:14px;--ms-table-line-height:1.3;--ms-table-pad-y:.42rem;--ms-table-pad-x:.55rem;--ms-cell-max-width:420px;--ms-cell-max-height:9rem;--ms-sql-editor-font-size:.9rem;--ms-sql-editor-min-height:220px}
    html[data-density="large"]{--sidebar:295px;--ms-table-font-size:16px;--ms-table-line-height:1.42;--ms-table-pad-y:.7rem;--ms-table-pad-x:.82rem;--ms-cell-max-width:560px;--ms-cell-max-height:12rem;--ms-sql-editor-font-size:1rem;--ms-sql-editor-min-height:280px;font-size:17px}html[data-density="large"] .main{padding:1.6rem}html[data-density="large"] .sidebar{padding:1.3rem!important}html[data-density="large"] .form-control,html[data-density="large"] .form-select,html[data-density="large"] .btn{font-size:1rem;padding:.58rem .8rem}html[data-density="large"] .card-body,html[data-density="large"] .card-header,html[data-density="large"] .card-footer{padding:1.25rem}html[data-density="large"] .nav-link,html[data-density="large"] .list-group-item{padding:.7rem .85rem}
    .ms-page-loader{position:fixed;inset:0;z-index:20000;display:flex;align-items:center;justify-content:center;background:color-mix(in srgb,var(--bs-body-bg) 88%,transparent);backdrop-filter:blur(3px);-webkit-backdrop-filter:blur(3px)}.ms-page-loader[hidden]{display:none!important}.ms-page-loader-box{min-width:280px;max-width:90vw;padding:2rem 2.5rem;border:1px solid var(--bs-border-color);border-radius:1rem;background:var(--bs-body-bg);box-shadow:0 1.5rem 4rem rgba(0,0,0,.22);text-align:center}.ms-page-spinner{width:5rem;height:5rem;margin:0 auto 1.25rem;border:.5rem solid rgba(var(--ms-accent-rgb),.18);border-top-color:var(--ms-accent);border-radius:50%;animation:ms-page-spin .8s linear infinite}.ms-page-loader-text{font-size:1.6rem;font-weight:700;letter-spacing:.01em;color:var(--bs-body-color)}@keyframes ms-page-spin{to{transform:rotate(360deg)}}@media(prefers-reduced-motion:reduce){.ms-page-spinner{animation-duration:1.6s}}
    .ms-sql-editor-wrap{position:relative;border-radius:var(--bs-border-radius);background:var(--bs-body-bg)}.ms-sql-highlight{position:absolute;inset:0;z-index:1;margin:0;box-sizing:border-box;border-style:solid;border-color:transparent;overflow:hidden;pointer-events:none;white-space:pre-wrap;overflow-wrap:break-word;word-break:normal;color:var(--bs-body-color);background:var(--bs-body-bg);border-radius:inherit}.ms-smart-sql-input{position:relative;z-index:2;background:transparent!important;color:transparent!important;-webkit-text-fill-color:transparent!important;caret-color:var(--bs-body-color);resize:vertical}.ms-smart-sql-input::selection{background:rgba(var(--ms-accent-rgb),.28)}.ms-sql-highlight .sql-k{color:#7c3aed;font-weight:700}.ms-sql-highlight .sql-t{color:#0f766e;font-weight:600}.ms-sql-highlight .sql-f{color:#2563eb}.ms-sql-highlight .sql-s{color:#b45309}.ms-sql-highlight .sql-i{color:#be185d}.ms-sql-highlight .sql-c{color:#6b7280;font-style:italic}.ms-sql-highlight .sql-n{color:#0891b2}.ms-sql-highlight .sql-v{color:#9333ea}.ms-sql-highlight .sql-o{color:#dc2626}.ms-sql-autocomplete{position:absolute;z-index:1200;min-width:280px;max-width:min(460px,calc(100% - 8px));max-height:280px;overflow:auto;border:1px solid var(--bs-border-color);border-radius:.55rem;background:var(--bs-body-bg);box-shadow:0 .8rem 2.2rem rgba(0,0,0,.22);padding:.3rem}.ms-sql-autocomplete[hidden]{display:none!important}.ms-sql-suggestion{display:flex;align-items:center;gap:.6rem;width:100%;border:0;border-radius:.35rem;background:transparent;color:var(--bs-body-color);text-align:left;padding:.48rem .6rem}.ms-sql-suggestion:hover,.ms-sql-suggestion.active{background:rgba(var(--ms-accent-rgb),.12)}.ms-sql-suggestion-icon{width:1.35rem;text-align:center;color:var(--ms-accent)}.ms-sql-suggestion-main{min-width:0;flex:1}.ms-sql-suggestion-name{display:block;font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace;font-weight:650;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.ms-sql-suggestion-meta{display:block;font-size:.75em;color:var(--bs-secondary-color);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.ms-sql-autocomplete-title{padding:.25rem .55rem .35rem;color:var(--bs-secondary-color);font-size:.75em;text-transform:uppercase;letter-spacing:.06em;font-weight:700}html[data-bs-theme="dark"] .ms-sql-highlight .sql-k{color:#c4b5fd}html[data-bs-theme="dark"] .ms-sql-highlight .sql-t{color:#5eead4}html[data-bs-theme="dark"] .ms-sql-highlight .sql-f{color:#93c5fd}html[data-bs-theme="dark"] .ms-sql-highlight .sql-s{color:#fbbf24}html[data-bs-theme="dark"] .ms-sql-highlight .sql-i{color:#f9a8d4}html[data-bs-theme="dark"] .ms-sql-highlight .sql-c{color:#94a3b8}html[data-bs-theme="dark"] .ms-sql-highlight .sql-n{color:#67e8f9}html[data-bs-theme="dark"] .ms-sql-highlight .sql-v{color:#d8b4fe}html[data-bs-theme="dark"] .ms-sql-highlight .sql-o{color:#fca5a5}
    .settings-choice{cursor:pointer;border:2px solid var(--bs-border-color);transition:border-color .15s,transform .15s}.settings-choice:hover{border-color:rgba(var(--ms-accent-rgb),.55);transform:translateY(-1px)}.btn-check:checked+.settings-choice{border-color:var(--ms-accent);box-shadow:0 0 0 .2rem rgba(var(--ms-accent-rgb),.15)}.scheme-swatch{height:2rem;border-radius:.4rem;background:var(--swatch);box-shadow:inset 0 0 0 1px rgba(0,0,0,.1)}
    html[data-pagination-position="top"] [data-ms-pagination="bottom"]{display:none!important}html[data-pagination-position="bottom"] [data-ms-pagination="top"]{display:none!important}.ms-date-editor .ms-picker-input[hidden],.ms-date-editor .ms-manual-input[hidden]{display:none!important}.ms-date-editor .ms-picker-toggle{min-width:2.45rem;padding-left:.55rem;padding-right:.55rem}.ms-date-editor .ms-picker-toggle i{margin:0!important}.ms-db-tools{align-items:flex-start;gap:0!important;font-size:.875em}.ms-db-tools .nav-link{display:inline-flex;align-items:center;width:auto!important;max-width:100%;white-space:nowrap;line-height:1.2}.ms-db-tools .nav-link i{font-size:1em}.ms-page-jump-item{display:flex;align-items:stretch}.ms-page-jump{width:5.25rem;min-width:5.25rem;text-align:center;border-radius:0!important;border-color:var(--bs-border-color);padding-left:.35rem!important;padding-right:.35rem!important}.ms-page-jump:focus{position:relative;z-index:4}.ms-page-jump-current{font-weight:700;color:var(--ms-link)}
    html[data-density="ultracompact"] .ms-db-tools .nav-link{line-height:1.1}html[data-density="ultracompact"] .ms-page-jump{width:4.25rem;min-width:4.25rem}html[data-density="compact"] .ms-db-tools .nav-link{line-height:1.15}html[data-density="compact"] .ms-page-jump{width:4.75rem;min-width:4.75rem}html[data-density="large"] .ms-db-tools .nav-link{line-height:1.25}html[data-density="large"] .ms-page-jump{width:6rem;min-width:6rem}
    @media(max-width:991.98px){.sidebar{position:static;width:auto;height:auto}.main{margin-left:0}.sidebar .nav{flex-direction:row;overflow:auto;flex-wrap:nowrap}.sidebar .nav-link{white-space:nowrap}}.ms-ios-switch{padding-left:3.4rem;min-height:1.75rem}.ms-ios-switch .form-check-input{width:2.9rem;height:1.65rem;margin-left:-3.4rem;margin-top:.05rem;border-radius:999px;cursor:pointer;box-shadow:none}.ms-ios-switch .form-check-input:focus{box-shadow:0 0 0 .2rem rgba(var(--ms-accent-rgb),.18)}.ms-ios-switch .form-check-label{cursor:pointer;line-height:1.75rem}@media print{.sidebar,.no-print{display:none!important}.main{margin:0;padding:0}.table-scroll{max-height:none;overflow:visible}}
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
<script src="https://cdn.jsdelivr.net/npm/sweetalert2@11"></script>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.8/dist/js/bootstrap.bundle.min.js"></script>
<script>
(() => {
  'use strict';
  document.querySelectorAll('[data-confirm]').forEach(el => el.addEventListener('click', e => {
    if (!confirm(el.dataset.confirm || 'Are you sure?')) e.preventDefault();
  }));
  document.addEventListener('click', async event => {
    const target = event.target instanceof Element ? event.target.closest('[data-ms-delete-single]') : null;
    if (!target) return;
    event.preventDefault();
    event.stopPropagation();
    if (!window.Swal || typeof window.Swal.fire !== 'function') return;
    const result = await window.Swal.fire({
      title: 'Delete this row?',
      text: 'This operation cannot be undone.',
      icon: 'warning',
      showCancelButton: true,
      confirmButtonText: 'Delete',
      cancelButtonText: 'Cancel',
      confirmButtonColor: '#dc3545',
      focusCancel: true,
      reverseButtons: true
    });
    if (result.isConfirmed && target.form) {
      if (typeof window.msShowPageLoader === 'function') window.msShowPageLoader('Deleting row...');
      target.form.requestSubmit(target);
    }
  });
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
  document.querySelectorAll('[data-ms-sidebar-object-toggle]').forEach(toggle=>{
    const tableName=toggle.dataset.msSidebarObjectToggle||'';
    if(!tableName)return;
    if(!settings.hiddenSidebarObjects||typeof settings.hiddenSidebarObjects!=='object'||Array.isArray(settings.hiddenSidebarObjects))settings.hiddenSidebarObjects={};
    toggle.checked=settings.hiddenSidebarObjects[tableName]!==true;
    toggle.addEventListener('change',async()=>{
      toggle.disabled=true;
      try{
        await window.msConfigPost('sidebar_visibility',{table:tableName,visible:toggle.checked?'1':'0'});
        if(toggle.checked)delete settings.hiddenSidebarObjects[tableName];
        else settings.hiddenSidebarObjects[tableName]=true;
        window.msApplySettings(settings);
      }catch(error){toggle.checked=!toggle.checked;alert(error.message||String(error));}
      finally{toggle.disabled=false;}
    });
  });
  document.querySelectorAll('[data-ms-page-jump]').forEach(input => {
    const goToPage = () => {
      const max = Math.max(1, Number.parseInt(input.dataset.msPages || '1', 10) || 1);
      let target = Number.parseInt(input.value, 10);
      if (!Number.isFinite(target)) return;
      target = Math.max(1, Math.min(max, target));
      input.value = String(target);
      const destination = new URL(window.location.href);
      destination.searchParams.set('p', String(target));
      if (typeof window.msShowPageLoader === 'function') window.msShowPageLoader('Changing page...');
      window.location.href = destination.toString();
    };
    input.addEventListener('keydown', event => {
      if (event.key !== 'Enter') return;
      event.preventDefault();
      goToPage();
    });
    input.addEventListener('change', goToPage);
  });

  const settingsForm=document.getElementById('ms-settings-form');
  if(settingsForm){
    const selectCurrent=()=>{
      const theme=settingsForm.querySelector(`[name="theme"][value="${settings.theme}"]`);
      const density=settingsForm.querySelector(`[name="density"][value="${settings.density}"]`);
      const scheme=settingsForm.querySelector(`[name="scheme"][value="${settings.scheme}"]`);
      const paginationPosition=settingsForm.querySelector(`[name="paginationPosition"][value="${settings.paginationPosition}"]`);
      if(theme)theme.checked=true;if(density)density.checked=true;if(scheme)scheme.checked=true;if(paginationPosition)paginationPosition.checked=true;
      settingsForm.elements.sqlRows.value=settings.sqlRows;
      settingsForm.elements.selectRows.value=settings.selectRows;
      settingsForm.elements.truncateCells.checked=!!settings.truncateCells;
      window.msSettingsMeta.menuKeys.forEach(key=>{const input=settingsForm.querySelector(`[name="menu[${key}]"]`);if(input)input.checked=!settings.menu||settings.menu[key]!==false;});
    };
    selectCurrent();
    const renderHiddenSidebarSettings=()=>{
      const hidden=settings.hiddenSidebarObjects&&typeof settings.hiddenSidebarObjects==='object'&&!Array.isArray(settings.hiddenSidebarObjects)?settings.hiddenSidebarObjects:{};
      const rows=Array.from(document.querySelectorAll('[data-ms-hidden-sidebar-row]'));
      let shown=0;
      rows.forEach(row=>{const isHidden=hidden[row.dataset.msHiddenSidebarKey]===true;row.hidden=!isHidden;if(isHidden)shown++;});
      const empty=document.getElementById('ms-hidden-sidebar-empty');
      const wrap=document.getElementById('ms-hidden-sidebar-table-wrap');
      if(empty)empty.hidden=shown!==0;
      if(wrap)wrap.hidden=shown===0;
      const showAll=document.getElementById('ms-sidebar-show-all-hidden');
      if(showAll)showAll.disabled=shown===0;
    };
    document.querySelectorAll('[data-ms-sidebar-restore]').forEach(button=>button.addEventListener('click',async()=>{
      const tableName=button.dataset.msSidebarRestore||'';
      if(!tableName)return;
      button.disabled=true;
      try{
        await window.msConfigPost('sidebar_visibility',{table:tableName,visible:'1'});
        if(settings.hiddenSidebarObjects)delete settings.hiddenSidebarObjects[tableName];
        window.msApplySettings(settings);renderHiddenSidebarSettings();
      }catch(error){alert(error.message||String(error));}
      finally{button.disabled=false;}
    }));
    const showAllHidden=document.getElementById('ms-sidebar-show-all-hidden');
    if(showAllHidden)showAllHidden.addEventListener('click',async()=>{
      const buttons=Array.from(document.querySelectorAll('[data-ms-sidebar-restore]')).filter(button=>settings.hiddenSidebarObjects&&settings.hiddenSidebarObjects[button.dataset.msSidebarRestore]===true);
      showAllHidden.disabled=true;
      try{
        for(const button of buttons){await window.msConfigPost('sidebar_visibility',{table:button.dataset.msSidebarRestore,visible:'1'});delete settings.hiddenSidebarObjects[button.dataset.msSidebarRestore];}
        window.msApplySettings(settings);renderHiddenSidebarSettings();
      }catch(error){alert(error.message||String(error));}
      finally{renderHiddenSidebarSettings();}
    });
    renderHiddenSidebarSettings();
    settingsForm.addEventListener('change',()=>{
      const preview={theme:settingsForm.elements.theme.value,density:settingsForm.elements.density.value,scheme:settingsForm.elements.scheme.value,sqlRows:Math.max(1,Math.min(100000,Number.parseInt(settingsForm.elements.sqlRows.value,10)||window.msSettingsMeta.defaults.sqlRows)),selectRows:Math.max(1,Math.min(500,Number.parseInt(settingsForm.elements.selectRows.value,10)||window.msSettingsMeta.defaults.selectRows)),paginationPosition:settingsForm.elements.paginationPosition.value,truncateCells:settingsForm.elements.truncateCells.checked,rawDbView:settings.rawDbView,menu:{},hiddenSidebarObjects:settings.hiddenSidebarObjects||{}};
      window.msSettingsMeta.menuKeys.forEach(key=>{const input=settingsForm.querySelector(`[name="menu[${key}]"]`);preview.menu[key]=!!(input&&input.checked);});
      window.msApplySettings(preview);
    });
    const showMenu=document.getElementById('ms-menu-show-all');
    if(showMenu)showMenu.addEventListener('click',()=>{window.msSettingsMeta.menuKeys.forEach(key=>{const input=settingsForm.querySelector(`[name="menu[${key}]"]`);if(input)input.checked=true;});settingsForm.dispatchEvent(new Event('change'));});
    const hideMenu=document.getElementById('ms-menu-hide-all');
    if(hideMenu)hideMenu.addEventListener('click',()=>{window.msSettingsMeta.menuKeys.forEach(key=>{const input=settingsForm.querySelector(`[name="menu[${key}]"]`);if(input)input.checked=false;});settingsForm.dispatchEvent(new Event('change'));});
    const reset=document.getElementById('ms-settings-reset');
    if(reset)reset.addEventListener('click',async()=>{
      if(!confirm('Restore every setting in the current profile to defaults? This also removes its saved column views, sidebar choices, saved widths, column order and saved searches.'))return;
      reset.disabled=true;
      try{await window.msConfigPost('reset_profile');location.reload();}
      catch(error){alert(error.message||String(error));reset.disabled=false;}
    });
  }
  document.querySelectorAll('[data-ms-table-layout]').forEach(table=>{
    let nativeColumns=[];
    try{nativeColumns=JSON.parse(table.dataset.msColumns||'[]');}catch(error){nativeColumns=[];}
    if(!Array.isArray(nativeColumns)||!nativeColumns.length||nativeColumns.some(column=>typeof column!=='string'))return;
    const context={database:table.dataset.msDatabase||'',table:table.dataset.msTable||''};
    if(!context.database||!context.table)return;
    let rawLayout={};
    try{rawLayout=JSON.parse(table.dataset.msLayout||'{}')||{};}catch(error){rawLayout={};}
    const normalizeLayout=raw=>{
      const order=[];const seen=new Set();
      if(raw&&Array.isArray(raw.order))raw.order.forEach(column=>{if(typeof column==='string'&&nativeColumns.includes(column)&&!seen.has(column)){order.push(column);seen.add(column);}});
      nativeColumns.forEach(column=>{if(!seen.has(column)){order.push(column);seen.add(column);}});
      const widths={};
      if(raw&&raw.widths&&typeof raw.widths==='object'&&!Array.isArray(raw.widths))Object.entries(raw.widths).forEach(([column,width])=>{const numeric=Number(width);if(nativeColumns.includes(column)&&Number.isFinite(numeric)&&numeric>=48&&numeric<=1200)widths[column]=numeric;});
      return {order,widths};
    };
    let layout=normalizeLayout(rawLayout);
    const cellsFor=column=>Array.from(table.querySelectorAll('[data-ms-column]')).filter(cell=>cell.dataset.msColumn===column);
    const setColumnWidth=(column,width)=>{const pixels=Math.max(48,Math.min(1200,Math.round(width)));cellsFor(column).forEach(cell=>{cell.style.width=`${pixels}px`;cell.style.minWidth=`${pixels}px`;cell.style.maxWidth=`${pixels}px`;});return pixels;};
    const applyOrder=order=>{table.querySelectorAll('tr').forEach(row=>{const cells=new Map(Array.from(row.children).filter(cell=>cell.dataset&&cell.dataset.msColumn).map(cell=>[cell.dataset.msColumn,cell]));order.forEach(column=>{const cell=cells.get(column);if(cell)row.appendChild(cell);});});};
    const currentFullOrder=()=>Array.isArray(layout.order)&&layout.order.length?[...layout.order]:[...nativeColumns];
    const mergeVisibleOrder=visibleOrder=>{const visibleSet=new Set(visibleOrder);let visibleIndex=0;return currentFullOrder().map(column=>visibleSet.has(column)?visibleOrder[visibleIndex++]:column);};
    applyOrder(layout.order);
    Object.entries(layout.widths).forEach(([column,width])=>setColumnWidth(column,Number(width)));
    const saveOrder=async()=>{
      const visibleOrder=Array.from(table.querySelectorAll('thead th[data-ms-column]')).map(th=>th.dataset.msColumn);
      layout.order=mergeVisibleOrder(visibleOrder);
      try{await window.msConfigPost('save_table_order',{table:context.table,order_json:JSON.stringify(layout.order)});}catch(error){console.error(error);}
    };
    const saveWidthsButton=Array.from(document.querySelectorAll('[data-ms-save-widths]')).find(button=>button.dataset.msSaveWidths===context.table);
    if(saveWidthsButton)saveWidthsButton.addEventListener('click',async()=>{
      const widths={};
      table.querySelectorAll('thead th[data-ms-column]').forEach(th=>{const width=Math.round(th.getBoundingClientRect().width);if(Number.isFinite(width))widths[th.dataset.msColumn]=Math.max(48,Math.min(1200,width));});
      const original=saveWidthsButton.innerHTML;saveWidthsButton.disabled=true;saveWidthsButton.innerHTML='<i class="fa-solid fa-spinner fa-spin me-1"></i>Saving';
      try{
        await window.msConfigPost('save_table_widths',{table:context.table,widths_json:JSON.stringify(widths)});
        layout.widths={...layout.widths,...widths};
        saveWidthsButton.innerHTML='<i class="fa-solid fa-check me-1"></i>Widths saved';
        setTimeout(()=>{saveWidthsButton.innerHTML=original;},1600);
      }catch(error){alert(error.message||String(error));saveWidthsButton.innerHTML=original;}
      finally{saveWidthsButton.disabled=false;}
    });
    const clearDropMarkers=()=>table.querySelectorAll('.ms-column-drop-before,.ms-column-drop-after').forEach(th=>th.classList.remove('ms-column-drop-before','ms-column-drop-after'));
    let draggedColumn='';
    table.querySelectorAll('thead th[data-ms-column]').forEach(th=>{
      th.addEventListener('dragstart',event=>{const target=event.target instanceof Element?event.target:null;if(!target||!target.closest('[data-ms-column-drag-handle]')){event.preventDefault();return;}draggedColumn=th.dataset.msColumn;th.classList.add('ms-column-dragging');event.dataTransfer.effectAllowed='move';event.dataTransfer.setData('text/plain',draggedColumn);});
      th.addEventListener('dragover',event=>{if(!draggedColumn||draggedColumn===th.dataset.msColumn)return;event.preventDefault();event.dataTransfer.dropEffect='move';clearDropMarkers();const rect=th.getBoundingClientRect();th.classList.add(event.clientX<rect.left+rect.width/2?'ms-column-drop-before':'ms-column-drop-after');});
      th.addEventListener('drop',event=>{if(!draggedColumn||draggedColumn===th.dataset.msColumn)return;event.preventDefault();const before=th.classList.contains('ms-column-drop-before');table.querySelectorAll('tr').forEach(row=>{const source=Array.from(row.children).find(cell=>cell.dataset&&cell.dataset.msColumn===draggedColumn);const target=Array.from(row.children).find(cell=>cell.dataset&&cell.dataset.msColumn===th.dataset.msColumn);if(source&&target)row.insertBefore(source,before?target:target.nextSibling);});clearDropMarkers();saveOrder();});
      th.addEventListener('dragend',()=>{draggedColumn='';th.classList.remove('ms-column-dragging');clearDropMarkers();});
      const handle=th.querySelector('[data-ms-col-resizer]');
      if(handle)handle.addEventListener('pointerdown',event=>{if(event.button!==0)return;event.preventDefault();event.stopPropagation();document.body.classList.add('ms-column-resizing');const startX=event.clientX,startWidth=th.getBoundingClientRect().width,column=th.dataset.msColumn;let finished=false;const move=moveEvent=>setColumnWidth(column,startWidth+moveEvent.clientX-startX);const finish=()=>{if(finished)return;finished=true;window.removeEventListener('pointermove',move);window.removeEventListener('pointerup',finish);window.removeEventListener('pointercancel',finish);document.body.classList.remove('ms-column-resizing');};window.addEventListener('pointermove',move);window.addEventListener('pointerup',finish);window.addEventListener('pointercancel',finish);});
    });
  });

  const savedSearchSelect=document.querySelector('[data-ms-saved-search-select]');
  if(savedSearchSelect){
    const saveButton=document.querySelector('[data-ms-save-search]');
    const loadButton=document.querySelector('[data-ms-load-search]');
    const deleteButton=document.querySelector('[data-ms-delete-search]');
    const nameInput=document.querySelector('[data-ms-search-name]');
    const queryForm=document.getElementById('ms-query-builder-form');
    if(loadButton)loadButton.addEventListener('click',()=>{const option=savedSearchSelect.selectedOptions[0];if(option&&option.value){if(typeof window.msShowPageLoader==='function')window.msShowPageLoader('Loading saved search...');location.href=option.value;}});
    if(saveButton&&nameInput&&queryForm)saveButton.addEventListener('click',async()=>{
      const name=nameInput.value.trim();if(!name){nameInput.focus();return;}
      const params=new URLSearchParams(new FormData(queryForm));const query={};
      for(const [rawKey,value] of params.entries()){
        if(rawKey==='page'||rawKey==='table'||rawKey==='p')continue;
        const isArray=rawKey.endsWith('[]');const key=isArray?rawKey.slice(0,-2):rawKey;
        if(isArray){if(!Array.isArray(query[key]))query[key]=[];query[key].push(value);}else query[key]=value;
      }
      saveButton.disabled=true;
      try{await window.msConfigPost('save_search',{table:saveButton.dataset.msSaveSearch,name,search_json:JSON.stringify(query)});location.reload();}
      catch(error){alert(error.message||String(error));saveButton.disabled=false;}
    });
    if(deleteButton)deleteButton.addEventListener('click',async()=>{
      const option=savedSearchSelect.selectedOptions[0];const name=option?option.dataset.searchName||'':'';if(!name)return;
      if(!confirm(`Delete saved search “${name}”?`))return;
      deleteButton.disabled=true;
      try{await window.msConfigPost('delete_search',{table:deleteButton.dataset.msDeleteSearch,name});location.reload();}
      catch(error){alert(error.message||String(error));deleteButton.disabled=false;}
    });
    savedSearchSelect.addEventListener('change',()=>{if(loadButton)loadButton.disabled=!savedSearchSelect.value;if(deleteButton)deleteButton.disabled=!savedSearchSelect.value;});
    if(loadButton)loadButton.disabled=!savedSearchSelect.value;
    if(deleteButton)deleteButton.disabled=!savedSearchSelect.value;
  }
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
  $rawDbView = ms_raw_db_view();
  $profileNames = ms_profile_names();
  $activeProfile = ms_active_profile_name();
  $hiddenSidebar = $dbName !== '' ? ms_profile_hidden_sidebar($dbName) : [];
  ?><aside class="sidebar p-3">
    <div class="mb-3">
      <div class="brand d-flex align-items-center gap-2"><a class="text-decoration-none" href="?page=databases"><i class="fa-solid fa-cube me-2"></i><?= h(MS_APP_NAME) ?></a><a class="badge text-bg-secondary fw-normal text-decoration-none" href="<?= h(url(['ms_check_update' => '1'])) ?>" title="Check for new version">v<?= h(MS_VERSION) ?></a></div>
      <div class="ms-raw-db-switch<?= $rawDbView ? ' is-active' : '' ?>" id="ms-raw-db-switch-box" title="Show raw database fields and values, temporarily ignoring all saved custom column views">
        <div class="form-check form-switch m-0 d-flex align-items-center gap-2">
          <input class="form-check-input m-0" type="checkbox" role="switch" id="ms-raw-db-view"<?= $rawDbView ? ' checked' : '' ?>>
          <label class="form-check-label small fw-semibold flex-grow-1" for="ms-raw-db-view"><i class="fa-solid fa-database me-1"></i>Raw DB view</label>
        </div>
        <div class="small text-body-secondary mt-1">Show all objects and ignore custom column views</div>
      </div>
    </div>
    <?php if ($dbName !== '') { ?><div class="small text-body-secondary mb-2 text-truncate" title="<?= h($dbName) ?>">Database: <strong><?= h($dbName) ?></strong></div><?php } ?>
    <nav class="nav nav-pills flex-column ms-db-tools small">
      <?php foreach ($items as [$key, $icon, $label]) { if ($dbName === '' && !in_array($key, ['databases', 'processes', 'users', 'variables'], true)) continue; ?>
        <a class="nav-link <?= $page === $key ? 'active' : 'text-body' ?>" data-ms-menu="<?= h($key) ?>" href="?page=<?= h($key) ?>"><i class="fa-solid <?= h($icon) ?> fa-fw me-2"></i><?= h($label) ?></a>
      <?php } ?>
    </nav>
    <?php if ($dbName !== '') {
      try {
        $sideDb = connect_db();
        $tables = db_all($sideDb, "SELECT TABLE_NAME, TABLE_TYPE FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() ORDER BY TABLE_NAME");
        ?><hr><div class="small text-uppercase text-body-secondary mb-2">Objects</div><div class="list-group list-group-flush small">
        <?php foreach ($tables as $t) {
          $name=(string)$t['TABLE_NAME'];
          $isBaseTable=(string)$t['TABLE_TYPE']==='BASE TABLE';
          $sidebarObjectHidden=!empty($hiddenSidebar[$name]);
          ?><div class="ms-sidebar-object-row" data-ms-sidebar-object-key="<?= h($name) ?>"<?= (!$rawDbView && $sidebarObjectHidden) ? ' hidden' : '' ?>>
            <a class="ms-sidebar-object-name text-truncate" title="<?= h($name) ?> · Show content" href="?page=select&amp;table=<?= urlencode($name) ?>"><i class="fa-solid <?= $isBaseTable?'fa-table':'fa-eye' ?> fa-fw me-1"></i><span class="text-truncate"><?= h($name) ?></span></a>
            <span class="ms-sidebar-object-actions">
              <a class="ms-sidebar-object-action" href="?page=select&amp;table=<?= urlencode($name) ?>" title="Show content: <?= h($name) ?>" aria-label="Show content of <?= h($name) ?>"><i class="fa-solid fa-table-cells" aria-hidden="true"></i></a>
              <?php if ($isBaseTable) { ?><a class="ms-sidebar-object-action" href="?page=structure&amp;table=<?= urlencode($name) ?>" title="Alter structure: <?= h($name) ?>" aria-label="Alter structure of <?= h($name) ?>"><i class="fa-solid fa-screwdriver-wrench" aria-hidden="true"></i></a><?php } ?>
            </span>
          </div><?php
        } ?>
        </div><?php
      } catch (Throwable $ignored) {}
    } ?>
    <hr><a class="nav-link mb-2 <?= $page === 'settings' ? 'active' : 'text-body' ?>" href="?page=settings"><i class="fa-solid fa-gear fa-fw me-2"></i>Settings</a>
    <div class="mb-3 ps-2">
      <?php if (count($profileNames) > 1) { ?>
        <form method="post" class="m-0"><input type="hidden" name="action" value="switch_profile"><?= csrf_field() ?><label class="form-label small text-body-secondary mb-1" for="ms-sidebar-profile">Profile</label><select class="form-select form-select-sm" id="ms-sidebar-profile" name="profile" onchange="this.form.submit()"><?php foreach($profileNames as $profileName){?><option value="<?= h($profileName) ?>"<?= $profileName===$activeProfile?' selected':'' ?>><?= h($profileName) ?></option><?php }?></select></form>
      <?php } else { ?><div class="small text-body-secondary">Profile: <strong class="text-body">Default</strong></div><?php } ?>
    </div>
    <form method="post"><input type="hidden" name="action" value="logout"><?= csrf_field() ?><button class="btn btn-secondary btn-sm w-100"><i class="fa-solid fa-right-from-bracket me-1"></i>Log out</button></form>
    <div class="small text-body-secondary mt-3"><a class="text-body-secondary text-decoration-none" href="<?= h(url(['ms_check_update' => '1'])) ?>" title="Check for new version">v<?= h(MS_VERSION) ?></a> · PHP 7.4+</div>
  </aside>
  <script>
  (()=>{
    'use strict';
    const toggle=document.getElementById('ms-raw-db-view');
    const box=document.getElementById('ms-raw-db-switch-box');
    if(!toggle)return;
    toggle.addEventListener('change',async()=>{
      toggle.disabled=true;
      try{
        await window.msConfigPost('raw_db_view',{enabled:toggle.checked?'1':'0'});
        if(box)box.classList.toggle('is-active',toggle.checked);
        if(typeof window.msShowPageLoader==='function')window.msShowPageLoader(toggle.checked?'Opening raw DB view...':'Restoring custom views...');
        location.reload();
      }catch(error){toggle.checked=!toggle.checked;toggle.disabled=false;alert(error.message||String(error));}
    });
  })();
  </script><?php
}

function title_bar(string $title, string $subtitle = '', string $actions = ''): void {
  ?><div class="d-flex flex-wrap justify-content-between align-items-start gap-3 mb-4"><div><h1 class="h3 mb-1"><?= h($title) ?></h1><?php if ($subtitle !== '') { ?><div class="text-body-secondary"><?= h($subtitle) ?></div><?php } ?></div><div class="no-print"><?= $actions ?></div></div><?php
}

function render_sql_results(array $results, float $time): void {
  ?><div class="alert alert-success">Completed in <?= h(number_format($time, 4)) ?> seconds.</div><?php
  foreach ($results as $i => $result) {
    ?><section class="card mb-3"><div class="card-header">Result <?= $i + 1 ?></div><div class="card-body p-0"><?php
    if ($result['fields']) {
      ?><div class="table-responsive"><table class="table table-sm table-striped mb-0 ms-data-table"><thead><tr><?php foreach ($result['fields'] as $field) { ?><th><?= h($field->name) ?></th><?php } ?></tr></thead><tbody><?php foreach ($result['rows'] as $row) { ?><tr><?php foreach ($row as $value) { ?><td><?= render_value($value) ?></td><?php } ?></tr><?php } ?></tbody></table></div>
      <div class="p-2 small d-flex flex-wrap justify-content-between align-items-center gap-2"><span class="text-body-secondary"><?php if (!empty($result['capped'])) { ?><?= h(number_format((int)$result['count'])) ?> total row(s); showing the first <?= h(number_format((int)($result['display_limit'] ?? MS_SQL_ROWS_DEFAULT))) ?>. Enable <strong>Show all result rows</strong> and run again to display every row.<?php } else { ?><?= h(number_format((int)($result['shown'] ?? count($result['rows'])))) ?> row(s) displayed.<?php } ?></span><?php if (!empty($result['export_token'])) { ?><span class="d-flex flex-wrap align-items-center gap-1"><span class="text-body-secondary me-1">Export all rows:</span><?php foreach (['sql' => 'SQL', 'csv' => 'CSV', 'tsv' => 'TSV'] as $format => $label) { ?><a class="btn btn-secondary btn-sm" href="?download=sql_result&amp;format=<?= h($format) ?>&amp;token=<?= h((string)$result['export_token']) ?>"><i class="fa-solid fa-download me-1"></i><?= h($label) ?></a><?php } ?></span><?php } ?></div><?php
    } else {
      ?><div class="p-3"><?= h((string)$result['affected']) ?> row(s) affected. <?= h((string)$result['info']) ?></div><?php
    }
    ?></div></section><?php
  }
}

function column_form_fields(mysqli $db, array $values = [], string $prefix = '', bool $showIndex = false): void {
  $name = (string)($values['name'] ?? '');
  $type = strtoupper((string)($values['type'] ?? 'VARCHAR'));
  $index = strtoupper((string)($values['index'] ?? ''));
  $field = static function (string $key) use ($prefix): string {
    return $prefix === '' ? $key : $prefix . $key . ']';
  };
  ?><div class="row g-2" data-ms-column-fields>
    <div class="col-md-2"><label class="form-label">Name</label><input class="form-control" name="<?= h($field('name')) ?>" value="<?= h($name) ?>" data-ms-column-name></div>
    <div class="col-md-2"><label class="form-label">Type</label><select class="form-select" name="<?= h($field('type')) ?>" data-ms-column-type><?php foreach (sql_type_options() as $option) { ?><option<?= $option===$type?' selected':'' ?>><?= h($option) ?></option><?php } ?></select></div>
    <div class="col-md-2"><label class="form-label">Length / ENUM lines</label><input class="form-control" name="<?= h($field('length')) ?>" value="<?= h($values['length'] ?? '') ?>" data-ms-column-length></div>
    <div class="col-md-2"><label class="form-label">Default</label><input class="form-control" name="<?= h($field('default')) ?>" value="<?= h($values['default'] ?? '') ?>"></div>
    <div class="col-md-2"><label class="form-label">Collation</label><input class="form-control" name="<?= h($field('collation')) ?>" value="<?= h($values['collation'] ?? '') ?>"></div>
    <div class="col-md-2"><label class="form-label">Comment</label><input class="form-control" name="<?= h($field('comment')) ?>" value="<?= h($values['comment'] ?? '') ?>"></div>
    <?php if ($showIndex) { ?><div class="col-md-2"><label class="form-label">Index</label><select class="form-select" name="<?= h($field('index')) ?>" data-ms-column-index><option value=""<?= $index===''?' selected':'' ?>>None</option><option value="PRIMARY"<?= $index==='PRIMARY'?' selected':'' ?>>PRIMARY</option><option value="INDEX"<?= $index==='INDEX'?' selected':'' ?>>INDEX</option><option value="UNIQUE"<?= $index==='UNIQUE'?' selected':'' ?>>UNIQUE</option></select></div><?php } ?>
    <div class="col-12 d-flex flex-wrap gap-3 small">
      <?php foreach ([['nullable','Nullable'],['default_set','Use default'],['default_expression','Default is expression'],['unsigned','Unsigned'],['auto_increment','Auto increment'],['on_update','ON UPDATE timestamp'],['invisible','Invisible'],['stored','Generated stored']] as [$key,$label]) { ?><label><input class="form-check-input" type="checkbox" name="<?= h($field($key)) ?>" value="1"<?= !empty($values[$key])?' checked':'' ?><?= $key==='nullable'?' data-ms-column-nullable':'' ?><?= $key==='auto_increment'?' data-ms-column-auto-increment':'' ?>> <?= h($label) ?></label><?php } ?>
    </div>
    <div class="col-md-8"><label class="form-label">Generated expression (leave empty for a normal column)</label><input class="form-control code" name="<?= h($field('generated')) ?>" value="<?= h($values['generated'] ?? '') ?>"></div>
  </div><?php
}

function page_login(string $error): void {
  $returnQuery = ms_decode_navigation(p('return_to'));
  if (!$returnQuery) {
    $returnQuery = ms_navigation_query($_GET);
  }
  $returnToken = ms_encode_navigation($returnQuery);
  page_head('Connect', false);
  ?><div class="row justify-content-center"><div class="col-lg-5 col-md-7"><?= ms_update_notice() ?><div class="text-center mb-4"><div class="display-5"><i class="fa-solid fa-cube text-primary"></i></div><h1 class="h2 d-flex justify-content-center align-items-center gap-2"><span><?= h(MS_APP_NAME) ?></span><span class="badge text-bg-secondary fs-6 fw-normal">v<?= h(MS_VERSION) ?></span></h1><p class="text-body-secondary">Single-file MySQL/MariaDB administration</p></div>
  <?php if ($error !== '') { ?><div class="alert alert-danger"><?= h($error) ?></div><?php } ?>
  <div class="card shadow-sm"><div class="card-body p-4"><form method="post" autocomplete="off"><input type="hidden" name="action" value="login"><?php if ($returnToken !== '') { ?><input type="hidden" name="return_to" value="<?= h($returnToken) ?>"><?php } ?><?= csrf_field() ?>
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
  ?><div class="card"><div class="table-responsive"><table class="table table-hover align-middle mb-0"><thead><tr><th>Name</th><th>Character set</th><th>Collation</th></tr></thead><tbody><?php foreach ($rows as $row) { ?><tr><td><form method="post" class="d-inline"><input type="hidden" name="action" value="select_db"><input type="hidden" name="database" value="<?= h($row['SCHEMA_NAME']) ?>"><?= csrf_field() ?><button class="btn btn-link p-0 border-0 align-baseline text-decoration-none fw-semibold" type="submit"><i class="fa-solid fa-database text-primary me-2"></i><?= h($row['SCHEMA_NAME']) ?></button></form></td><td><?= h($row['DEFAULT_CHARACTER_SET_NAME']) ?></td><td><?= h($row['DEFAULT_COLLATION_NAME']) ?></td></tr><?php } ?></tbody></table></div></div>
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

  $isRetry = p('action') === 'create_table';
  $tableName = $isRetry ? p('name') : '';
  $engine = $isRetry ? p('engine', 'InnoDB') : 'InnoDB';
  $collation = $isRetry ? p('collation', 'utf8mb4_unicode_ci') : 'utf8mb4_unicode_ci';
  $comment = $isRetry ? p('comment') : '';
  $postedColumns = $isRetry && isset($_POST['columns']) && is_array($_POST['columns']) ? $_POST['columns'] : [];

  if ($postedColumns) {
    $rows = array_values(array_filter($postedColumns, 'is_array'));
  } else {
    $rows = [
      ['name'=>'id', 'type'=>'INT', 'length'=>'', 'nullable'=>false, 'auto_increment'=>true, 'index'=>'PRIMARY'],
      ['name'=>'', 'type'=>'VARCHAR', 'length'=>'255', 'nullable'=>true, 'index'=>''],
      ['name'=>'', 'type'=>'VARCHAR', 'length'=>'255', 'nullable'=>true, 'index'=>''],
      ['name'=>'', 'type'=>'VARCHAR', 'length'=>'255', 'nullable'=>true, 'index'=>''],
      ['name'=>'', 'type'=>'VARCHAR', 'length'=>'255', 'nullable'=>true, 'index'=>''],
      ['name'=>'', 'type'=>'VARCHAR', 'length'=>'255', 'nullable'=>true, 'index'=>'']
    ];
  }
  if (!$rows) {
    $rows[] = ['name'=>'id', 'type'=>'INT', 'length'=>'', 'nullable'=>false, 'auto_increment'=>true, 'index'=>'PRIMARY'];
  }
  ?><form method="post" id="msCreateTableForm">
    <input type="hidden" name="action" value="create_table"><?= csrf_field() ?>
    <div class="card mb-3"><div class="card-body"><div class="row g-3">
      <div class="col-md-4"><label class="form-label">Table name</label><input class="form-control" name="name" value="<?= h($tableName) ?>" required autofocus></div>
      <div class="col-md-3"><label class="form-label">Engine</label><input class="form-control" name="engine" value="<?= h($engine) ?>"></div>
      <div class="col-md-3"><label class="form-label">Collation</label><input class="form-control" name="collation" value="<?= h($collation) ?>"></div>
      <div class="col-md-2"><label class="form-label">Comment</label><input class="form-control" name="comment" value="<?= h($comment) ?>"></div>
    </div></div></div>

    <div class="alert alert-info py-2 small"><i class="fa-solid fa-circle-info me-2"></i>The first field is ready as <code>id INT NOT NULL AUTO_INCREMENT PRIMARY KEY</code>. The Index selector is part of table creation, so AUTO_INCREMENT fields are never sent to MySQL without a key.</div>

    <div id="msCreateTableColumns"><?php foreach ($rows as $i => $row) { ?>
      <div class="card mb-2" data-ms-create-column><div class="card-header py-2 d-flex justify-content-between align-items-center"><strong data-ms-column-title>Field <?= h((string)($i + 1)) ?></strong><button class="btn btn-outline-danger btn-sm" type="button" data-ms-remove-column title="Remove this field"><i class="fa-solid fa-xmark"></i></button></div><div class="card-body"><?php column_form_fields($db, $row, 'columns['.$i.'][', true); ?></div></div>
    <?php } ?></div>

    <div class="d-flex flex-wrap gap-2 mt-3"><button class="btn btn-secondary" type="button" id="msAddCreateColumn"><i class="fa-solid fa-plus me-1"></i>Add field</button><button class="btn btn-primary" type="submit"><i class="fa-solid fa-table me-1"></i>Create table</button></div>
  </form>

  <template id="msCreateColumnTemplate"><div class="card mb-2" data-ms-create-column><div class="card-header py-2 d-flex justify-content-between align-items-center"><strong data-ms-column-title>Field</strong><button class="btn btn-outline-danger btn-sm" type="button" data-ms-remove-column title="Remove this field"><i class="fa-solid fa-xmark"></i></button></div><div class="card-body"><?php column_form_fields($db, ['name'=>'','type'=>'VARCHAR','length'=>'255','nullable'=>true,'index'=>''], 'columns[__INDEX__][', true); ?></div></div></template>
  <script>
  (()=>{
    'use strict';
    const container=document.getElementById('msCreateTableColumns');
    const addButton=document.getElementById('msAddCreateColumn');
    const template=document.getElementById('msCreateColumnTemplate');
    if(!container||!addButton||!template)return;

    let nextIndex=0;
    container.querySelectorAll('[name]').forEach(el=>{
      const match=(el.getAttribute('name')||'').match(/^columns\[(\d+)\]/);
      if(match)nextIndex=Math.max(nextIndex,Number(match[1])+1);
    });

    const lengthDefaults={VARCHAR:'255',VARBINARY:'255',CHAR:'1',BINARY:'1',DECIMAL:'10,2',DEC:'10,2',NUMERIC:'10,2',FIXED:'10,2',BIT:'1',VECTOR:'3'};
    const parameterTypes=new Set(['VARCHAR','VARBINARY','CHAR','BINARY','DECIMAL','DEC','NUMERIC','FIXED','BIT','ENUM','SET','DATETIME','TIMESTAMP','TIME','VECTOR']);

    const syncType=card=>{
      const type=card.querySelector('[data-ms-column-type]');
      const length=card.querySelector('[data-ms-column-length]');
      if(!type||!length)return;
      const value=String(type.value||'').toUpperCase();
      if(value==='ENUM'||value==='SET'){
        length.value='';
        length.placeholder='one value per line';
      }else if(parameterTypes.has(value)){
        length.placeholder=value==='DATETIME'||value==='TIMESTAMP'||value==='TIME'?'0-6':'';
        length.value=Object.prototype.hasOwnProperty.call(lengthDefaults,value)?lengthDefaults[value]:'';
      }else{
        length.value='';
        length.placeholder='';
      }
    };

    const enforceAutoIncrement=card=>{
      const auto=card.querySelector('[data-ms-column-auto-increment]');
      const nullable=card.querySelector('[data-ms-column-nullable]');
      const index=card.querySelector('[data-ms-column-index]');
      if(!auto||!auto.checked)return;
      if(nullable)nullable.checked=false;
      if(index&&index.value==='')index.value='INDEX';
    };

    const renumber=()=>{
      const cards=Array.from(container.querySelectorAll('[data-ms-create-column]'));
      cards.forEach((card,i)=>{
        const title=card.querySelector('[data-ms-column-title]');
        if(title)title.textContent='Field '+(i+1);
      });
      cards.forEach(card=>{
        const remove=card.querySelector('[data-ms-remove-column]');
        if(remove)remove.disabled=cards.length<=1;
      });
    };

    const bind=card=>{
      const type=card.querySelector('[data-ms-column-type]');
      const auto=card.querySelector('[data-ms-column-auto-increment]');
      if(type)type.addEventListener('change',()=>syncType(card));
      if(auto)auto.addEventListener('change',()=>enforceAutoIncrement(card));
      const remove=card.querySelector('[data-ms-remove-column]');
      if(remove)remove.addEventListener('click',()=>{card.remove();renumber();});
      enforceAutoIncrement(card);
    };

    container.querySelectorAll('[data-ms-create-column]').forEach(bind);
    addButton.addEventListener('click',()=>{
      const html=template.innerHTML.replaceAll('__INDEX__',String(nextIndex++));
      const holder=document.createElement('div');
      holder.innerHTML=html.trim();
      const card=holder.firstElementChild;
      if(!card)return;
      container.appendChild(card);
      bind(card);
      renumber();
      const input=card.querySelector('[data-ms-column-name]');
      if(input)input.focus();
    });
    renumber();
  })();
  </script><?php
}

function exact_column_definition(mysqli $db, string $table, string $columnName): string {
  $row = db_one($db, 'SHOW CREATE TABLE ' . qi($table));
  if (!$row) {
    throw new RuntimeException('Unable to read the table definition.');
  }
  $create = '';
  foreach ($row as $key => $value) {
    if (stripos((string)$key, 'Create ') === 0) {
      $create = (string)$value;
      break;
    }
  }
  if ($create === '') {
    throw new RuntimeException('Unable to read the table definition.');
  }
  $escaped = preg_quote(str_replace('`', '``', $columnName), '/');
  if (preg_match('/^\s*`' . $escaped . '`\s+([^\r\n]+)$/m', $create, $match) !== 1) {
    throw new RuntimeException('Unable to reconstruct the column definition safely.');
  }
  $definition = trim((string)$match[1]);
  if (substr($definition, -1) === ',') {
    $definition = rtrim(substr($definition, 0, -1));
  }
  if ($definition === '') {
    throw new RuntimeException('The column definition is empty.');
  }
  return $definition;
}

function parse_column_meta(array $column): array {
  $type = strtoupper((string)$column['DATA_TYPE']);
  $length = '';
  if (in_array($type,['CHAR','VARCHAR','BINARY','VARBINARY'],true)) $length=(string)$column['CHARACTER_MAXIMUM_LENGTH'];
  elseif (in_array($type,['DECIMAL','NUMERIC'],true)) $length=$column['NUMERIC_PRECISION'].','.$column['NUMERIC_SCALE'];
  elseif (in_array($type,['ENUM','SET'],true) && preg_match('/^[^(]+\((.*)\)$/s',(string)$column['COLUMN_TYPE'],$m)) $length=str_replace(["','","'"],["\n",''],$m[1]);
  return ['name'=>$column['COLUMN_NAME'],'type'=>$type,'length'=>$length,'nullable'=>$column['IS_NULLABLE']==='YES','default_set'=>$column['COLUMN_DEFAULT']!==null,'default'=>$column['COLUMN_DEFAULT']??'','default_expression'=>preg_match('/CURRENT_TIMESTAMP|^\(.+\)$/i',(string)($column['COLUMN_DEFAULT']??''))===1,'unsigned'=>strpos((string)$column['COLUMN_TYPE'],'unsigned')!==false,'auto_increment'=>strpos((string)$column['EXTRA'],'auto_increment')!==false,'on_update'=>stripos((string)$column['EXTRA'],'on update')!==false,'invisible'=>stripos((string)$column['EXTRA'],'invisible')!==false,'collation'=>$column['COLLATION_NAME']??'','comment'=>$column['COLUMN_COMMENT'],'generated'=>$column['GENERATION_EXPRESSION']??'','stored'=>strpos((string)$column['EXTRA'],'STORED')!==false];
}

function column_is_numeric_type(string $type): bool {
  return in_array(strtolower($type), [
    'bit','tinyint','smallint','mediumint','int','integer','bigint','decimal','dec','numeric','fixed',
    'float','double','double precision','real','bool','boolean'
  ], true);
}

function column_is_text_type(string $type): bool {
  return in_array(strtolower($type), [
    'char','varchar','tinytext','text','mediumtext','longtext','enum','set'
  ], true);
}

function column_is_temporal_type(string $type): bool {
  return in_array(strtolower($type), ['date','datetime','timestamp','time','year'], true);
}

function column_is_spatial_type(string $type): bool {
  return in_array(strtolower($type), [
    'geometry','point','linestring','polygon','multipoint','multilinestring','multipolygon','geometrycollection'
  ], true);
}

function column_is_binary_type(string $type): bool {
  return in_array(strtolower($type), [
    'binary','varbinary','tinyblob','blob','mediumblob','longblob'
  ], true);
}

function column_statistics_summary(mysqli $db, string $table, array $column): array {
  $name = (string)$column['COLUMN_NAME'];
  $type = strtolower((string)$column['DATA_TYPE']);
  $value = qi($name);
  $distinctExpression = $value;
  if ($type === 'json') {
    $distinctExpression = 'CAST(' . $value . ' AS CHAR)';
  } elseif (column_is_spatial_type($type)) {
    $distinctExpression = 'ST_AsBinary(' . $value . ')';
  }
  $parts = [
    'COUNT(*) AS total_rows',
    'COUNT(' . $value . ') AS non_null_rows',
    'SUM(' . $value . ' IS NULL) AS null_rows',
    'COUNT(DISTINCT ' . $distinctExpression . ') AS distinct_values'
  ];
  $comparable = column_is_numeric_type($type) || column_is_text_type($type) || column_is_temporal_type($type) || in_array($type, ['binary','varbinary'], true);
  if ($comparable) {
    $parts[] = 'MIN(' . $value . ') AS min_value';
    $parts[] = 'MAX(' . $value . ') AS max_value';
  }
  if (column_is_numeric_type($type)) {
    $parts[] = 'AVG(' . $value . ') AS avg_value';
    $parts[] = 'STDDEV_POP(' . $value . ') AS stddev_value';
    $parts[] = 'SUM(' . $value . ') AS sum_value';
    $parts[] = 'SUM(' . $value . ' = 0) AS zero_rows';
    $parts[] = 'SUM(' . $value . ' < 0) AS negative_rows';
  }
  if (column_is_text_type($type)) {
    $parts[] = 'AVG(CHAR_LENGTH(' . $value . ')) AS avg_length';
    $parts[] = 'MIN(CHAR_LENGTH(' . $value . ')) AS min_length';
    $parts[] = 'MAX(CHAR_LENGTH(' . $value . ')) AS max_length';
    $parts[] = 'SUM(' . $value . " = '') AS empty_rows";
  }
  if (column_is_binary_type($type)) {
    $parts[] = 'AVG(OCTET_LENGTH(' . $value . ')) AS avg_bytes';
    $parts[] = 'MIN(OCTET_LENGTH(' . $value . ')) AS min_bytes';
    $parts[] = 'MAX(OCTET_LENGTH(' . $value . ')) AS max_bytes';
    $parts[] = 'SUM(OCTET_LENGTH(' . $value . ') = 0) AS empty_rows';
  }
  $started = microtime(true);
  $row = db_one($db, 'SELECT ' . implode(', ', $parts) . ' FROM ' . qi($table));
  if (!$row) {
    throw new RuntimeException('Unable to calculate column statistics.');
  }
  $row['_time'] = microtime(true) - $started;
  return $row;
}

function column_distinct_select_parts(array $column): array {
  $name = (string)$column['COLUMN_NAME'];
  $type = strtolower((string)$column['DATA_TYPE']);
  $value = qi($name);
  if (column_is_spatial_type($type)) {
    return ['IF(' . $value . ' IS NULL, NULL, HEX(ST_AsBinary(' . $value . ')))', 'ST_AsBinary(' . $value . ')'];
  }
  if (column_is_binary_type($type)) {
    return ['IF(' . $value . ' IS NULL, NULL, HEX(' . $value . '))', $value];
  }
  if ($type === 'json') {
    return ['CAST(' . $value . ' AS CHAR)', 'CAST(' . $value . ' AS CHAR)'];
  }
  return [$value, $value];
}

function stats_number($value, int $decimals = 2): string {
  if ($value === null || $value === '') {
    return '—';
  }
  if (is_numeric($value)) {
    return number_format((float)$value, $decimals, '.', ',');
  }
  return (string)$value;
}

function render_stat_box(string $label, string $value, string $hint = ''): void {
  ?><div class="col-6 col-md-4 col-xl-3"><div class="border rounded p-2 h-100"><div class="small text-body-secondary"><?= h($label) ?></div><div class="fw-semibold text-break"><?= h($value) ?></div><?php if ($hint !== '') { ?><div class="small text-body-secondary mt-1"><?= h($hint) ?></div><?php } ?></div></div><?php
}

function render_column_statistics(mysqli $db, string $table, array $column, bool $expandDistinct): void {
  $name = (string)$column['COLUMN_NAME'];
  $type = strtolower((string)$column['DATA_TYPE']);
  try {
    $stats = column_statistics_summary($db, $table, $column);
  } catch (Throwable $e) {
    ?><div class="alert alert-danger mb-0"><strong>Statistics failed:</strong> <?= h($e->getMessage()) ?></div><?php
    return;
  }
  $total = (int)($stats['total_rows'] ?? 0);
  $nonNull = (int)($stats['non_null_rows'] ?? 0);
  $nulls = (int)($stats['null_rows'] ?? 0);
  $distinct = (int)($stats['distinct_values'] ?? 0);
  $nullPct = $total > 0 ? ($nulls * 100 / $total) : 0.0;
  $uniquePct = $nonNull > 0 ? ($distinct * 100 / $nonNull) : 0.0;
  $keyLabel = (string)($column['COLUMN_KEY'] ?? '');
  $keyText = $keyLabel === 'PRI' ? 'Primary key' : ($keyLabel === 'UNI' ? 'Unique index' : ($keyLabel === 'MUL' ? 'Indexed' : 'Not indexed'));
  ?><div class="card border-info-subtle mt-3 mb-1 ms-column-statistics">
    <div class="card-header d-flex flex-wrap justify-content-between align-items-center gap-2"><div><strong><i class="fa-solid fa-chart-column me-2"></i>Statistics: <?= h($name) ?></strong><span class="text-body-secondary ms-2"><?= h((string)$column['COLUMN_TYPE']) ?></span></div><span class="small text-body-secondary">Calculated in <?= h(number_format((float)$stats['_time'], 4)) ?> s</span></div>
    <div class="card-body">
      <div class="row g-2 mb-3"><?php
        render_stat_box('Rows', number_format($total));
        render_stat_box('Non-NULL', number_format($nonNull));
        render_stat_box('NULL', number_format($nulls), number_format($nullPct, 2) . '% of rows');
        render_stat_box('Distinct non-NULL', number_format($distinct), number_format($uniquePct, 2) . '% of non-NULL values');
        render_stat_box('Index status', $keyText);
        render_stat_box('Nullable', ((string)$column['IS_NULLABLE'] === 'YES') ? 'Yes' : 'No');
        if (array_key_exists('min_value', $stats)) render_stat_box('Minimum', $stats['min_value'] === null ? '—' : (string)$stats['min_value']);
        if (array_key_exists('max_value', $stats)) render_stat_box('Maximum', $stats['max_value'] === null ? '—' : (string)$stats['max_value']);
        if (column_is_numeric_type($type)) {
          render_stat_box('Average', stats_number($stats['avg_value'] ?? null, 6));
          render_stat_box('Std. deviation', stats_number($stats['stddev_value'] ?? null, 6), 'Population standard deviation');
          render_stat_box('Sum', stats_number($stats['sum_value'] ?? null, 6));
          render_stat_box('Zero values', number_format((int)($stats['zero_rows'] ?? 0)));
          render_stat_box('Negative values', number_format((int)($stats['negative_rows'] ?? 0)));
        }
        if (column_is_text_type($type)) {
          render_stat_box('Average length', stats_number($stats['avg_length'] ?? null, 2) . ' chars');
          render_stat_box('Shortest length', stats_number($stats['min_length'] ?? null, 0) . ' chars');
          render_stat_box('Longest length', stats_number($stats['max_length'] ?? null, 0) . ' chars');
          render_stat_box('Empty strings', number_format((int)($stats['empty_rows'] ?? 0)));
        }
        if (column_is_binary_type($type)) {
          render_stat_box('Average size', stats_number($stats['avg_bytes'] ?? null, 2) . ' bytes');
          render_stat_box('Smallest size', stats_number($stats['min_bytes'] ?? null, 0) . ' bytes');
          render_stat_box('Largest size', stats_number($stats['max_bytes'] ?? null, 0) . ' bytes');
          render_stat_box('Empty values', number_format((int)($stats['empty_rows'] ?? 0)));
        }
      ?></div>
      <?php
      $showDistinct = $distinct < 10 || $expandDistinct;
      if (!$showDistinct) {
        $expandUrl = '?' . http_build_query(['page'=>'structure','table'=>$table,'stats'=>$name,'distinct'=>'all']) . '#ms-column-' . substr(sha1($name), 0, 16);
        ?><div class="alert alert-warning d-flex flex-wrap justify-content-between align-items-center gap-2 mb-0"><span><i class="fa-solid fa-triangle-exclamation me-2"></i>This column has <?= h(number_format($distinct)) ?> distinct non-NULL values. Expanding all frequencies can take significant time and may generate a very large page.</span><a class="btn btn-warning btn-sm" href="<?= h($expandUrl) ?>" data-confirm="This will group and display every distinct value in this column. On a large table this can take a long time and produce a very large response. Continue?"><i class="fa-solid fa-list me-1"></i>Expand all distinct values</a></div><?php
      } else {
        [$displayExpression, $groupExpression] = column_distinct_select_parts($column);
        $sql = 'SELECT ' . $displayExpression . ' AS value_display, COUNT(*) AS occurrences FROM ' . qi($table) . ' GROUP BY ' . $groupExpression . ' ORDER BY occurrences DESC';
        $started = microtime(true);
        $result = $db->query($sql, MYSQLI_USE_RESULT);
        if (!$result instanceof mysqli_result) {
          ?><div class="alert alert-danger mb-0">Unable to calculate value frequencies: <?= h($db->error) ?></div><?php
        } else {
          ?><div class="d-flex flex-wrap justify-content-between align-items-center gap-2 mb-2"><strong>Value frequencies</strong><span class="small text-body-secondary"><?= $distinct < 10 ? 'Shown automatically because there are fewer than 10 distinct non-NULL values.' : 'All distinct values requested explicitly.' ?></span></div>
          <div class="table-responsive border rounded" style="max-height:32rem"><table class="table table-sm table-striped align-middle mb-0"><thead class="sticky-top"><tr><th>Value</th><th class="text-end">Count</th><th class="text-end">Percent</th></tr></thead><tbody><?php
          while ($frequency = $result->fetch_assoc()) {
            $count = (int)$frequency['occurrences'];
            $percent = $total > 0 ? ($count * 100 / $total) : 0.0;
            ?><tr><td class="code"><?php if ($frequency['value_display'] === null) { ?><span class="badge text-bg-secondary">NULL</span><?php } else { echo render_value($frequency['value_display'], 1000); } ?></td><td class="text-end"><?= h(number_format($count)) ?></td><td class="text-end"><?= h(number_format($percent, 4)) ?>%</td></tr><?php
          }
          $result->free();
          ?></tbody></table></div><div class="small text-body-secondary mt-2">Frequency query completed in <?= h(number_format(microtime(true) - $started, 4)) ?> s.</div><?php
        }
      }
      ?>
    </div>
  </div><?php
}

function page_structure(mysqli $db): void {
  $table=g('table'); if(!table_exists($db,$table)) throw new RuntimeException('Table not found.');
  $columns=table_columns($db,$table); $status=db_one($db,'SHOW TABLE STATUS LIKE '.qs($db,$table));
  $createRow=db_one($db,'SHOW CREATE TABLE '.qi($table));
  $createSql=(string)($createRow['Create Table']??'');
  if($createSql==='') throw new RuntimeException('Unable to read the CREATE TABLE statement.');
  $createSql=rtrim($createSql,"; \t\r\n").';';
  $indexes=db_all($db,'SHOW INDEX FROM '.qi($table));
  $foreign=db_all($db,"SELECT CONSTRAINT_NAME,COLUMN_NAME,REFERENCED_TABLE_NAME,REFERENCED_COLUMN_NAME,ORDINAL_POSITION FROM information_schema.KEY_COLUMN_USAGE WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=".qs($db,$table)." AND REFERENCED_TABLE_NAME IS NOT NULL ORDER BY CONSTRAINT_NAME,ORDINAL_POSITION");
  $checks=db_all($db,"SELECT tc.CONSTRAINT_NAME,cc.CHECK_CLAUSE FROM information_schema.TABLE_CONSTRAINTS tc JOIN information_schema.CHECK_CONSTRAINTS cc ON cc.CONSTRAINT_SCHEMA=tc.CONSTRAINT_SCHEMA AND cc.CONSTRAINT_NAME=tc.CONSTRAINT_NAME WHERE tc.TABLE_SCHEMA=DATABASE() AND tc.TABLE_NAME=".qs($db,$table)." AND tc.CONSTRAINT_TYPE='CHECK'");
  $triggers=db_all($db,'SELECT TRIGGER_NAME,ACTION_TIMING,EVENT_MANIPULATION,ACTION_STATEMENT FROM information_schema.TRIGGERS WHERE TRIGGER_SCHEMA=DATABASE() AND EVENT_OBJECT_TABLE='.qs($db,$table));
  $statsColumn=g('stats');
  $columnNames=array_map('strval',array_column($columns,'COLUMN_NAME'));
  if($statsColumn!==''&&!in_array($statsColumn,$columnNames,true)) $statsColumn='';
  $expandDistinct=$statsColumn!==''&&g('distinct')==='all';
  $structureActions='<div class="d-flex flex-wrap gap-2">' .
    '<a class="btn btn-primary" href="?page=select&amp;table='.urlencode($table).'">Browse data</a>' .
    '<a class="btn btn-secondary" href="?download=table_structure_sql&amp;table='.urlencode($table).'" title="Download the exact CREATE TABLE statement"><i class="fa-solid fa-download me-1"></i>Download SQL</a>' .
    '<button class="btn btn-secondary" type="button" id="msCopyCreateTableSql" title="Copy the exact CREATE TABLE statement to the clipboard"><i class="fa-solid fa-copy me-1"></i>Copy SQL</button>' .
    '</div>';
  title_bar('Structure: '.$table, $status['Comment']??'', $structureActions);
  ?><textarea id="msCreateTableSql" class="visually-hidden" tabindex="-1" aria-hidden="true"><?= h($createSql) ?></textarea><style>
    .ms-structure-column-handle{cursor:grab;touch-action:none;min-width:2.5rem;border:0;border-right:1px solid var(--bs-border-color);background:transparent;color:var(--bs-secondary-color)}
    .ms-structure-column-handle:active{cursor:grabbing}.ms-structure-column.ms-structure-dragging{opacity:.45}.ms-structure-column.ms-structure-drop-before{box-shadow:inset 0 3px 0 var(--ms-accent)}.ms-structure-column.ms-structure-drop-after{box-shadow:inset 0 -3px 0 var(--ms-accent)}
    .ms-structure-column{scroll-margin-top:.75rem}.ms-structure-column .accordion-button{min-width:0;padding:var(--ms-table-pad-y) var(--ms-table-pad-x);font-size:var(--ms-table-font-size);line-height:var(--ms-table-line-height);min-height:0}.ms-structure-column .accordion-button::after{width:1rem;height:1rem;background-size:1rem}.ms-structure-column-handle{padding:var(--ms-table-pad-y) var(--ms-table-pad-x);font-size:var(--ms-table-font-size);line-height:var(--ms-table-line-height)}.ms-column-statistics .sticky-top{z-index:1}
    html[data-density="ultracompact"] .ms-structure-column-handle{min-width:1.8rem}html[data-density="compact"] .ms-structure-column-handle{min-width:2rem}html[data-density="standard"] .ms-structure-column-handle{min-width:2.5rem}html[data-density="large"] .ms-structure-column-handle{min-width:3rem}
  </style>
  <ul class="nav nav-tabs mb-3"><li class="nav-item"><button class="nav-link active" data-bs-toggle="tab" data-bs-target="#columns">Columns</button></li><li class="nav-item"><button class="nav-link" data-bs-toggle="tab" data-bs-target="#indexes">Indexes</button></li><li class="nav-item"><button class="nav-link" data-bs-toggle="tab" data-bs-target="#foreign">Foreign keys</button></li><li class="nav-item"><button class="nav-link" data-bs-toggle="tab" data-bs-target="#checks">Checks</button></li><li class="nav-item"><button class="nav-link" data-bs-toggle="tab" data-bs-target="#table-triggers">Triggers</button></li><li class="nav-item"><button class="nav-link" data-bs-toggle="tab" data-bs-target="#partitions">Partitions</button></li><li class="nav-item"><button class="nav-link" data-bs-toggle="tab" data-bs-target="#table-settings">Table</button></li></ul>
  <div class="tab-content"><div class="tab-pane fade show active" id="columns">
    <div class="alert alert-info py-2 small"><i class="fa-solid fa-grip-vertical me-2"></i>Drag a column by its grip to change the physical column order in the database. Reordering executes an <code>ALTER TABLE</code>, so very large tables may take time or require a table rebuild depending on the server/version.</div>
    <form method="post" id="msColumnReorderForm" class="d-none"><input type="hidden" name="action" value="reorder_column"><input type="hidden" name="column" value=""><input type="hidden" name="after" value=""><?= csrf_field() ?></form>
    <div class="accordion" id="columnAccordion" data-ms-structure-columns><?php
      foreach($columns as $i=>$column){
        $meta=parse_column_meta($column);
        $columnName=(string)$column['COLUMN_NAME'];
        $showStats=$statsColumn===$columnName;
        $columnAnchor='ms-column-'.substr(sha1($columnName),0,16);
        ?><div class="accordion-item ms-structure-column" id="<?= h($columnAnchor) ?>" data-ms-structure-column="<?= h($columnName) ?>"<?= $showStats?' data-ms-stats-active="1"':'' ?>><h2 class="accordion-header d-flex"><button type="button" class="ms-structure-column-handle" draggable="true" data-ms-structure-handle title="Drag to reorder column" aria-label="Drag <?= h($columnName) ?> to reorder"><i class="fa-solid fa-grip-vertical"></i></button><button class="accordion-button collapsed" data-bs-toggle="collapse" data-bs-target="#col<?= $i ?>"><span class="code text-truncate"><?= h($columnName.' '.$column['COLUMN_TYPE']) ?></span><?php if($column['COLUMN_KEY']){?><span class="badge text-bg-primary ms-2"><?= h($column['COLUMN_KEY']) ?></span><?php }?></button></h2><div id="col<?= $i ?>" class="accordion-collapse collapse<?= $showStats?' show':'' ?>" data-bs-parent="#columnAccordion"><div class="accordion-body">
          <form method="post"><input type="hidden" name="action" value="alter_column"><input type="hidden" name="old_name" value="<?= h($columnName) ?>"><?= csrf_field() ?><?php column_form_fields($db,$meta); ?><div class="row mt-2"><div class="col-md-3"><label class="form-label">Position</label><select class="form-select" name="position"><option value="">Keep</option><option value="FIRST">First</option><?php foreach($columns as $c){if($c['COLUMN_NAME']!==$columnName){?><option value="<?= h($c['COLUMN_NAME']) ?>">After <?= h($c['COLUMN_NAME']) ?></option><?php }}?></select></div><div class="col-md-9 d-flex align-items-end"><button class="btn btn-primary">Save column</button></div></div></form>
          <div class="d-flex flex-wrap gap-2 mt-2"><a class="btn btn-info" href="?<?= h(http_build_query(['page'=>'structure','table'=>$table,'stats'=>$columnName])) ?>#<?= h($columnAnchor) ?>"><i class="fa-solid fa-chart-column me-1"></i>Statistics</a><form method="post"><input type="hidden" name="action" value="drop_column"><input type="hidden" name="column" value="<?= h($columnName) ?>"><?= csrf_field() ?><button class="btn btn-danger" data-confirm="Drop this column and its data?">Drop</button></form></div>
          <?php if($showStats) render_column_statistics($db,$table,$column,$expandDistinct); ?>
        </div></div></div><?php
      }
    ?></div>
    <div class="card mt-3"><div class="card-header">Add column</div><div class="card-body"><form method="post"><input type="hidden" name="action" value="add_column"><?= csrf_field() ?><?php column_form_fields($db,['type'=>'VARCHAR','length'=>'255','nullable'=>true]); ?><div class="row mt-2"><div class="col-md-3"><select class="form-select" name="position"><option value="">At end</option><option value="FIRST">First</option><?php foreach($columns as $c){?><option value="<?= h($c['COLUMN_NAME']) ?>">After <?= h($c['COLUMN_NAME']) ?></option><?php }?></select></div><div class="col"><button class="btn btn-primary">Add column</button></div></div></form></div></div>
    <div class="card mt-3" id="msQuickColumns"><div class="card-header d-flex align-items-center gap-2"><i class="fa-solid fa-bolt"></i><strong>Quick field operations</strong></div><div class="card-body"><p class="text-body-secondary small mb-2">This section is only for quick clone/delete operations and quick renaming. For the details and properties of each field, use the column properties above.</p><form method="post" id="msQuickRenameForm" class="d-none"><input type="hidden" name="action" value="quick_rename_column"><input type="hidden" name="column" value=""><input type="hidden" name="new_name" value=""><?= csrf_field() ?></form><div class="table-responsive"><table class="table table-hover align-middle mb-0"><thead><tr><th>Field</th><th>Type</th><th class="text-end">Quick actions</th></tr></thead><tbody><?php foreach($columns as $column){$quickName=(string)$column['COLUMN_NAME'];?><tr><td><button type="button" class="btn btn-link p-0 border-0 text-decoration-none code" data-ms-quick-rename="<?= h($quickName) ?>" title="Click to rename"><?= h($quickName) ?></button></td><td><span class="code"><?= h((string)$column['COLUMN_TYPE']) ?></span></td><td class="text-end"><div class="d-inline-flex gap-1"><form method="post" class="d-inline"><input type="hidden" name="action" value="quick_clone_column"><input type="hidden" name="column" value="<?= h($quickName) ?>"><?= csrf_field() ?><button class="btn btn-outline-secondary btn-sm" type="submit" title="Clone <?= h($quickName) ?>" aria-label="Clone <?= h($quickName) ?>"><i class="fa-solid fa-clone"></i></button></form><form method="post" class="d-inline"><input type="hidden" name="action" value="drop_column"><input type="hidden" name="column" value="<?= h($quickName) ?>"><?= csrf_field() ?><button class="btn btn-outline-danger btn-sm" type="submit" data-confirm="Drop column <?= h($quickName) ?> and all its data?" title="Delete <?= h($quickName) ?>" aria-label="Delete <?= h($quickName) ?>"><i class="fa-solid fa-trash"></i></button></form></div></td></tr><?php }?></tbody></table></div></div></div>
  </div>
  <div class="tab-pane fade" id="indexes"><?php render_indexes($db,$table,$indexes,$columns); ?></div>
  <div class="tab-pane fade" id="foreign"><?php render_foreign_keys($db,$table,$foreign,$columns); ?></div>
  <div class="tab-pane fade" id="checks"><?php render_checks($db,$checks); ?></div>
  <div class="tab-pane fade" id="table-triggers"><?php render_table_triggers($triggers); ?></div>
  <div class="tab-pane fade" id="partitions"><?php render_partitions($db,$table); ?></div>
  <div class="tab-pane fade" id="table-settings"><?php render_table_settings($db,$table,$status); ?></div></div>
  <script>
  (()=>{
    'use strict';
    const copyButton=document.getElementById('msCopyCreateTableSql');
    const sqlSource=document.getElementById('msCreateTableSql');
    if(copyButton&&sqlSource){
      copyButton.addEventListener('click',async()=>{
        const sql=sqlSource.value;
        const original=copyButton.innerHTML;
        let copied=false;
        try{
          if(navigator.clipboard&&window.isSecureContext){
            await navigator.clipboard.writeText(sql);
            copied=true;
          }
        }catch(error){}
        if(!copied){
          const helper=document.createElement('textarea');
          helper.value=sql;
          helper.setAttribute('readonly','');
          helper.style.position='fixed';
          helper.style.opacity='0';
          helper.style.pointerEvents='none';
          document.body.appendChild(helper);
          helper.select();
          helper.setSelectionRange(0,helper.value.length);
          try{copied=document.execCommand('copy');}catch(error){copied=false;}
          helper.remove();
        }
        if(copied){
          copyButton.innerHTML='<i class="fa-solid fa-check me-1"></i>Copied';
          copyButton.classList.remove('btn-secondary');
          copyButton.classList.add('btn-success');
          window.setTimeout(()=>{
            copyButton.innerHTML=original;
            copyButton.classList.remove('btn-success');
            copyButton.classList.add('btn-secondary');
          },1800);
        }else if(window.Swal&&typeof window.Swal.fire==='function'){
          window.Swal.fire({icon:'error',title:'Copy failed',text:'The browser did not allow clipboard access.'});
        }else{
          alert('The browser did not allow clipboard access.');
        }
      });
    }
    const quickRenameForm=document.getElementById('msQuickRenameForm');
    if(quickRenameForm){
      document.querySelectorAll('[data-ms-quick-rename]').forEach(button=>{
        button.addEventListener('click',()=>{
          const oldName=button.dataset.msQuickRename||'';
          const newName=window.prompt('Rename column:',oldName);
          if(newName===null)return;
          const trimmed=newName.trim();
          if(!trimmed||trimmed===oldName)return;
          quickRenameForm.querySelector('input[name="column"]').value=oldName;
          quickRenameForm.querySelector('input[name="new_name"]').value=trimmed;
          quickRenameForm.submit();
        });
      });
    }
    const list=document.querySelector('[data-ms-structure-columns]');
    const form=document.getElementById('msColumnReorderForm');
    if(!list||!form)return;
    const activeStats=list.querySelector('[data-ms-stats-active="1"]');
    if(activeStats){
      requestAnimationFrame(()=>requestAnimationFrame(()=>activeStats.scrollIntoView({block:'start',inline:'nearest'})));
    }
    const columnInput=form.querySelector('input[name="column"]');
    const afterInput=form.querySelector('input[name="after"]');
    let dragged=null;
    const clear=()=>list.querySelectorAll('.ms-structure-column').forEach(item=>item.classList.remove('ms-structure-drop-before','ms-structure-drop-after'));
    list.querySelectorAll('[data-ms-structure-handle]').forEach(handle=>{
      handle.addEventListener('dragstart',event=>{
        dragged=handle.closest('.ms-structure-column');
        if(!dragged)return;
        dragged.classList.add('ms-structure-dragging');
        event.dataTransfer.effectAllowed='move';
        event.dataTransfer.setData('text/plain',dragged.dataset.msStructureColumn||'');
      });
      handle.addEventListener('dragend',()=>{
        if(dragged)dragged.classList.remove('ms-structure-dragging');
        clear();dragged=null;
      });
    });
    list.querySelectorAll('.ms-structure-column').forEach(item=>{
      const dropTarget=item.querySelector('.accordion-header');
      if(!dropTarget)return;
      dropTarget.addEventListener('dragover',event=>{
        if(!dragged||dragged===item)return;
        event.preventDefault();event.dataTransfer.dropEffect='move';clear();
        const rect=dropTarget.getBoundingClientRect();
        const before=event.clientY<rect.top+rect.height/2;
        item.classList.add(before?'ms-structure-drop-before':'ms-structure-drop-after');
      });
      dropTarget.addEventListener('drop',event=>{
        if(!dragged||dragged===item)return;
        event.preventDefault();
        const rect=dropTarget.getBoundingClientRect();
        const before=event.clientY<rect.top+rect.height/2;
        if(before)list.insertBefore(dragged,item);else list.insertBefore(dragged,item.nextSibling);
        clear();
        const previous=dragged.previousElementSibling;
        columnInput.value=dragged.dataset.msStructureColumn||'';
        afterInput.value=previous&&previous.classList.contains('ms-structure-column')?(previous.dataset.msStructureColumn||''):'';
        if(typeof window.msShowPageLoader==='function')window.msShowPageLoader('Reordering column...');
        form.submit();
      });
    });
  })();
  </script><?php
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

function build_select_query(mysqli $db,string $table,array $columns,?int $overrideOffset=null,?int $overrideLimit=null): array {
  $allowed=array_column($columns,'COLUMN_NAME');
  $where=[]; $filterCols=$_GET['filter_col']??[]; $filterOps=$_GET['filter_op']??[]; $filterValues=$_GET['filter_val']??[];
  if(!is_array($filterCols))$filterCols=[]; if(!is_array($filterOps))$filterOps=[]; if(!is_array($filterValues))$filterValues=[];
  $operators=['='=>'=','!='=>'<>','>'=>'>','>='=>'>=','<'=>'<','<='=>'<=','contains'=>'LIKE','starts'=>'LIKE','ends'=>'LIKE','null'=>'IS NULL','not_null'=>'IS NOT NULL','regexp'=>'REGEXP','fulltext'=>'MATCH'];
  foreach($filterCols as $i=>$column){$column=(string)$column;if(!in_array($column,$allowed,true))continue;$op=(string)($filterOps[$i]??'=');if(!isset($operators[$op]))continue;$sqlOp=$operators[$op];if(in_array($op,['null','not_null'],true)){$where[]=qi($column).' '.$sqlOp;continue;}$value=(string)($filterValues[$i]??'');if($op==='fulltext'){$where[]='MATCH('.qi($column).') AGAINST ('.qs($db,$value).' IN BOOLEAN MODE)';continue;}if($op==='contains')$value='%'.$value.'%';if($op==='starts')$value=$value.'%';if($op==='ends')$value='%'.$value;$where[]=qi($column).' '.$sqlOp.' '.qs($db,$value);}
  $aggregate=strtoupper(g('aggregate'));$aggregateColumn=g('aggregate_column');$groupColumn=g('group_column');$validAgg=['COUNT','SUM','AVG','MIN','MAX'];
  $select='*';$group='';
  if(in_array($aggregate,$validAgg,true)&&in_array($aggregateColumn,$allowed,true)){$select=($groupColumn!==''&&in_array($groupColumn,$allowed,true)?qi($groupColumn).', ':'').$aggregate.'('.qi($aggregateColumn).') AS '.qi(strtolower($aggregate).'_'.$aggregateColumn);if($groupColumn!==''&&in_array($groupColumn,$allowed,true))$group=' GROUP BY '.qi($groupColumn);}
  $orderParts=[];$orderCols=$_GET['order_col']??[];$orderDirs=$_GET['order_dir']??[];if(!is_array($orderCols))$orderCols=[];if(!is_array($orderDirs))$orderDirs=[];foreach($orderCols as $i=>$column){if(in_array($column,$allowed,true))$orderParts[]=qi((string)$column).' '.(strtoupper((string)($orderDirs[$i]??'ASC'))==='DESC'?'DESC':'ASC');}
  $defaultLimit=ms_profile_setting_int('selectRows',MS_ROWS_PER_PAGE,1,500);$limit=max(1,min(500,(int)g('limit',(string)$defaultLimit)));$showAll=g('show_all')==='1';$page=$showAll?1:max(1,(int)g('p','1'));$offset=$overrideOffset!==null?max(0,$overrideOffset):(($page-1)*$limit);$queryLimit=$overrideLimit!==null?max(1,min(5000,$overrideLimit)):$limit;
  $from=' FROM '.qi($table).($where?' WHERE '.implode(' AND ',$where):'');
  $sql='SELECT '.$select.$from.$group.($orderParts?' ORDER BY '.implode(', ',$orderParts):'').($showAll?'':' LIMIT '.$offset.','.$queryLimit);
  $countSql=$group!==''?'SELECT COUNT(*) AS n FROM (SELECT 1'.$from.$group.') ms_groups':'SELECT COUNT(*) AS n'.$from;
  return [$sql,$countSql,$limit,$page,$where,$aggregate!==''&&in_array($aggregate,$validAgg,true),$showAll];
}

function render_select_pagination(int $page, int $pages, string $position): void {
  $pages = max(1, $pages);
  $page = max(1, min($pages, $page));
  $manyPages = $pages > 6;
  $firstPages = $manyPages ? range(1, min(3, $pages)) : range(1, $pages);
  $lastPages = $manyPages ? range(max(4, $pages - 2), $pages) : [];
  $edgePages = array_values(array_unique(array_merge($firstPages, $lastPages)));
  $middleCurrent = $manyPages && !in_array($page, $edgePages, true);

  $renderPage = static function (int $number, int $current, int $total): void {
    $active = $number === $current;
    ?><li class="page-item <?= $active ? 'active' : '' ?>"><a class="page-link d-flex align-items-center gap-1" href="<?= h(url(['p' => $number])) ?>"<?= $active ? ' aria-current="page"' : '' ?> title="Page <?= h((string)$number) ?>"><?php if ($number === 1) { ?><i class="fa-solid fa-backward-fast" aria-hidden="true"></i><?php } ?><span><?= h((string)$number) ?></span><?php if ($number === $total) { ?><i class="fa-solid fa-forward-fast" aria-hidden="true"></i><?php } ?></a></li><?php
  };

  ?><nav class="my-3 no-print" aria-label="Table pages" data-ms-pagination="<?= h($position) ?>"><ul class="pagination mb-0 flex-wrap"><?php
    foreach ($firstPages as $number) {
      $renderPage((int)$number, $page, $pages);
    }

    if ($manyPages) {
      ?><li class="page-item ms-page-jump-item"><input class="form-control ms-page-jump<?= $middleCurrent ? ' ms-page-jump-current' : '' ?>" type="number" inputmode="numeric" min="1" max="<?= h((string)$pages) ?>" step="1"<?= $middleCurrent ? ' value="' . h((string)$page) . '"' : '' ?> placeholder="Page" title="Enter a page number from 1 to <?= h((string)$pages) ?> and press Enter" aria-label="Go to page" data-ms-page-jump data-ms-pages="<?= h((string)$pages) ?>"></li><?php
      foreach ($lastPages as $number) {
        $renderPage((int)$number, $page, $pages);
      }
    }
  ?></ul></nav><?php
}

function ms_render_select_rows_html(mysqli $db,string $table,array $columns,array $rows,bool $editable,bool $aggregated,array $hiddenColumns,array $imageColumns,array $softFkRules,array $softFkMaps,array $formatRules,array $relations,array $returnQuery,string $returnToken): string {
  $primary = primary_columns($db, $table) ?: array_column($columns, 'COLUMN_NAME');
  $columnMap = [];
  foreach ($columns as $column) {
    $columnMap[(string)$column['COLUMN_NAME']] = $column;
  }
  ob_start();
  foreach ($rows as $row) {
    $identity = [];
    foreach ($primary as $key) {
      $identity[(string)$key] = $row[$key] ?? null;
    }
    $encoded = encode_identity($identity);
    $viewUrl = '?' . http_build_query(['page'=>'row','mode'=>'view','table'=>$table,'id'=>$encoded,'return_to'=>$returnToken]);
    $editUrl = '?' . http_build_query(['page'=>'row','mode'=>'edit','table'=>$table,'id'=>$encoded,'return_to'=>$returnToken]);
    $cloneUrl = '?' . http_build_query(['page'=>'row','mode'=>'clone','table'=>$table,'id'=>$encoded,'return_to'=>$returnToken]);
    $deleteQuery = $returnQuery;
    $deleteQuery['single_id'] = $encoded;
    $deleteUrl = '?' . http_build_query($deleteQuery);
    ?><tr><?php if (!$aggregated) { ?>
      <?php if ($editable) { ?><td data-ms-static-column="selection"><input class="form-check-input row-check" type="checkbox" name="row_id[]" value="<?= h($encoded) ?>"></td><?php } ?>
      <td class="ms-row-actions-cell" data-ms-static-column="actions"><span class="ms-row-actions">
        <a class="ms-row-action" href="<?= h($viewUrl) ?>" title="View row" aria-label="View row"><i class="fa-solid fa-eye"></i></a>
        <?php if ($editable) { ?>
          <a class="ms-row-action" href="<?= h($editUrl) ?>" title="Edit row" aria-label="Edit row"><i class="fa-solid fa-pen"></i></a>
          <a class="ms-row-action" href="<?= h($cloneUrl) ?>" title="Clone row" aria-label="Clone row"><i class="fa-solid fa-clone"></i></a>
          <button class="ms-row-action ms-row-delete" type="submit" name="action" value="delete_row" formaction="<?= h($deleteUrl) ?>" data-ms-delete-single title="Delete row" aria-label="Delete row"><i class="fa-solid fa-trash"></i></button>
        <?php } ?>
      </span></td>
    <?php }
    foreach ($row as $name => $value) {
      $name = (string)$name;
      if (!$aggregated && !empty($hiddenColumns[$name])) continue;
      $colMeta = $columnMap[$name] ?? null;
      ?><td<?php if (!$aggregated) { ?> data-ms-column="<?= h($name) ?>"<?php } ?>><?php
      if (!$aggregated && isset($formatRules[$name]) && is_array($formatRules[$name])) {
        echo ms_render_formatted_value($value, $formatRules[$name]);
      } elseif (!$aggregated && isset($imageColumns[$name]) && is_array($imageColumns[$name])) {
        echo ms_render_image_value($value, $imageColumns[$name]);
      } elseif (!$aggregated && isset($softFkRules[$name]) && is_array($softFkRules[$name]) && $value !== null) {
        $soft = $softFkRules[$name];
        $map = $softFkMaps[$name] ?? [];
        $key = (string)$value;
        $found = array_key_exists($key, $map);
        $display = $found ? $map[$key] : $value;
        $relUrl = '?' . http_build_query(['page'=>'select','table'=>(string)($soft['table']??''),'filter_col'=>[(string)($soft['id_column']??'')],'filter_op'=>['='],'filter_val'=>[(string)$value]]);
        ?><a href="<?= h($relUrl) ?>" title="Soft foreign key: <?= h($name) ?> = <?= h((string)$value) ?>"><?= render_value($display) ?> <i class="fa-solid <?= $found?'fa-link':'fa-link-slash' ?> small"></i></a><?php
      } elseif ($colMeta && preg_match('/blob|binary/i', (string)$colMeta['DATA_TYPE']) && $value !== null) {
        ?><a href="?download=blob&amp;table=<?= urlencode($table) ?>&amp;column=<?= urlencode($name) ?>&amp;id=<?= urlencode($encoded) ?>"><i class="fa-solid fa-download me-1"></i><?= h(strlen((string)$value)) ?> bytes</a><?php
      } elseif (isset($relations[$name]) && $value !== null) {
        $rel = $relations[$name];
        $relUrl = '?' . http_build_query(['page'=>'select','table'=>$rel['REFERENCED_TABLE_NAME'],'filter_col'=>[$rel['REFERENCED_COLUMN_NAME']],'filter_op'=>['='],'filter_val'=>[(string)$value]]);
        ?><a href="<?= h($relUrl) ?>" title="Open referenced row"><?= render_value($value) ?> <i class="fa-solid fa-arrow-up-right-from-square small"></i></a><?php
      } else {
        echo render_value($value);
      }
      ?></td><?php
    }
    ?></tr><?php
  }
  return (string)ob_get_clean();
}

function page_select(mysqli $db): void {
  $table=g('table');if(!table_exists($db,$table))throw new RuntimeException('Table or view not found.');$columns=table_columns($db,$table);$meta=db_one($db,'SELECT TABLE_TYPE FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='.qs($db,$table));$editable=($meta['TABLE_TYPE']??'')==='BASE TABLE';
  $relations=[];foreach(db_all($db,"SELECT COLUMN_NAME,REFERENCED_TABLE_NAME,REFERENCED_COLUMN_NAME FROM information_schema.KEY_COLUMN_USAGE WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=".qs($db,$table)." AND REFERENCED_TABLE_NAME IS NOT NULL") as $relation){$relations[$relation['COLUMN_NAME']]=$relation;}
  [$sql,$countSql,$limit,$page,$where,$aggregated,$showAll]=build_select_query($db,$table,$columns);$rows=db_all($db,$sql);$totalRow=db_one($db,$countSql);$total=(int)($totalRow['n']??0);$pages=$showAll?1:max(1,(int)ceil($total/$limit));$initialOffset=$showAll?0:(($page-1)*$limit);$nextOffset=$initialOffset+count($rows);$moreRowsDefault=ms_profile_setting_int('selectRows',MS_ROWS_PER_PAGE,1,500);$hasMoreRows=!$showAll&&$nextOffset<$total;
  $emptyViewConfig=['hidden'=>[],'images'=>[],'soft_fk'=>[],'formats'=>[],'labels'=>[]];
  $storedViewConfig=$aggregated?$emptyViewConfig:ms_column_view_table_config(selected_db(),$table);
  $viewConfig=(!$aggregated&&ms_raw_db_view())?$emptyViewConfig:$storedViewConfig;
  $hiddenColumns=is_array($viewConfig['hidden']??null)?$viewConfig['hidden']:[];$imageColumns=is_array($viewConfig['images']??null)?$viewConfig['images']:[];$softFkRules=is_array($viewConfig['soft_fk']??null)?$viewConfig['soft_fk']:[];$formatRules=is_array($viewConfig['formats']??null)?$viewConfig['formats']:[];$labelRules=is_array($viewConfig['labels']??null)?$viewConfig['labels']:[];
  $storedHiddenColumns=is_array($storedViewConfig['hidden']??null)?$storedViewConfig['hidden']:[];$storedImageColumns=is_array($storedViewConfig['images']??null)?$storedViewConfig['images']:[];$storedSoftFkRules=is_array($storedViewConfig['soft_fk']??null)?$storedViewConfig['soft_fk']:[];$storedFormatRules=is_array($storedViewConfig['formats']??null)?$storedViewConfig['formats']:[];$storedLabelRules=is_array($storedViewConfig['labels']??null)?$storedViewConfig['labels']:[];
  $allColumnNames=array_values(array_map('strval',array_column($columns,'COLUMN_NAME')));$visibleColumnNames=$aggregated?$allColumnNames:array_values(array_filter($allColumnNames,static function(string $column) use($hiddenColumns):bool{return empty($hiddenColumns[$column]);}));
  $headers=$rows?array_keys($rows[0]):$visibleColumnNames;if(!$aggregated)$headers=array_values(array_filter($headers,static function($header) use($hiddenColumns):bool{return empty($hiddenColumns[(string)$header]);}));
  $softFkMaps=$aggregated?[]:ms_soft_fk_maps($db,$rows,$softFkRules);
  $layoutColumns=$allColumnNames;$layoutColumnsJson=json_encode($layoutColumns,JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES)?:'[]';$savedLayout=ms_profile_table_layout(selected_db(),$table);$savedLayoutJson=json_encode($savedLayout,JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES)?:'{}';$sidebarHidden=!empty(ms_profile_hidden_sidebar(selected_db())[$table]);$savedSearches=ms_profile_table_saved_searches(selected_db(),$table);
  $softTargetTables=array_values(array_map('strval',array_column(db_all($db,'SELECT TABLE_NAME FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() ORDER BY TABLE_NAME'),'TABLE_NAME')));
  $returnQuery=ms_navigation_query($_GET);if(!$returnQuery)$returnQuery=['page'=>'select','table'=>$table];$returnToken=ms_encode_navigation($returnQuery);
  $actions='<div class="d-inline-flex align-items-center me-2"><div class="form-check form-switch ms-ios-switch m-0"><input class="form-check-input" type="checkbox" role="switch" id="ms-sidebar-object-visible" data-ms-sidebar-object-toggle="'.h($table).'"'.($sidebarHidden?'':' checked').'><label class="form-check-label text-nowrap" for="ms-sidebar-object-visible">Left sidebar</label></div></div> ';if(!$aggregated)$actions.='<button class="btn btn-secondary" type="button" data-ms-save-widths="'.h($table).'"><i class="fa-solid fa-arrows-left-right-to-line me-1"></i>Save Widths</button> ';$actions.='<a class="btn btn-secondary" href="?page=structure&amp;table='.urlencode($table).'">Structure</a> ';
  if($showAll){$actions.='<a class="btn btn-secondary" href="'.h(url(['show_all'=>null,'p'=>null,'limit'=>null])).'"><i class="fa-solid fa-layer-group me-1"></i>Use pagination</a> ';}else{$actions.='<a class="btn btn-secondary" data-confirm="Show all '.number_format($total).' rows? Large results can use substantial browser and server memory." href="'.h(url(['show_all'=>'1','p'=>null])).'"><i class="fa-solid fa-list me-1"></i>Show all rows</a> ';}
  if($editable)$actions.='<a class="btn btn-primary" href="?page=row&amp;mode=insert&amp;table='.urlencode($table).'&amp;return_to='.urlencode($returnToken).'"><i class="fa-solid fa-plus me-1"></i>Insert row</a>';
  title_bar($table,number_format($total).' result(s)',$actions);
  ?><div class="card mb-3 no-print"><div class="card-header"><button class="btn btn-sm btn-secondary" data-bs-toggle="collapse" data-bs-target="#queryBuilder"><i class="fa-solid fa-filter me-1"></i>Search, aggregate, sort and limit</button></div><div class="collapse <?= $where||g('aggregate')!==''||$showAll?'show':'' ?>" id="queryBuilder"><div class="card-body">
    <div class="row g-2 align-items-end mb-3 pb-3 border-bottom">
      <div class="col-md-4"><label class="form-label" for="ms-saved-search-select">Saved search</label><select class="form-select" id="ms-saved-search-select" data-ms-saved-search-select><option value="">Choose saved search…</option><?php foreach($savedSearches as $searchName=>$searchQuery){$savedUrl='?'.http_build_query(array_merge(['page'=>'select','table'=>$table],is_array($searchQuery)?$searchQuery:[]));?><option value="<?= h($savedUrl) ?>" data-search-name="<?= h((string)$searchName) ?>"><?= h((string)$searchName) ?></option><?php }?></select></div>
      <div class="col-md-4"><label class="form-label" for="ms-search-name">Save current search as</label><input class="form-control" id="ms-search-name" data-ms-search-name maxlength="100" placeholder="Search name"></div>
      <div class="col-md-auto"><button class="btn btn-outline-primary" type="button" data-ms-save-search="<?= h($table) ?>"><i class="fa-solid fa-floppy-disk me-1"></i>Save search</button></div>
      <div class="col-md-auto"><button class="btn btn-secondary" type="button" data-ms-load-search disabled><i class="fa-solid fa-folder-open me-1"></i>Load</button></div>
      <div class="col-md-auto"><button class="btn btn-outline-danger" type="button" data-ms-delete-search="<?= h($table) ?>" disabled><i class="fa-solid fa-trash me-1"></i>Delete</button></div>
    </div>
    <form method="get" id="ms-query-builder-form"><input type="hidden" name="page" value="select"><input type="hidden" name="table" value="<?= h($table) ?>"><h3 class="h6">Filters</h3><?php for($i=0;$i<3;$i++){?><div class="row g-2 mb-2"><div class="col-md-3"><select class="form-select" name="filter_col[]"><option value="">Column…</option><?php foreach($columns as $c){$name=$c['COLUMN_NAME'];?><option value="<?= h($name) ?>"<?= (($_GET['filter_col'][$i]??'')===$name)?' selected':'' ?>><?= h($name) ?></option><?php }?></select></div><div class="col-md-2"><select class="form-select" name="filter_op[]"><?php foreach(['=','!=','>','>=','<','<=','contains','starts','ends','regexp','fulltext','null','not_null'] as $op){?><option<?= (($_GET['filter_op'][$i]??'')===$op)?' selected':'' ?>><?= h($op) ?></option><?php }?></select></div><div class="col-md-7"><input class="form-control" name="filter_val[]" value="<?= h($_GET['filter_val'][$i]??'') ?>"></div></div><?php }?><hr><div class="row g-2"><div class="col-md-2"><label class="form-label">Aggregate</label><select class="form-select" name="aggregate"><option value="">None</option><?php foreach(['COUNT','SUM','AVG','MIN','MAX'] as $a){?><option<?= g('aggregate')===$a?' selected':'' ?>><?= $a ?></option><?php }?></select></div><div class="col-md-3"><label class="form-label">Aggregate column</label><select class="form-select" name="aggregate_column"><?php foreach($columns as $c){?><option<?= g('aggregate_column')===$c['COLUMN_NAME']?' selected':'' ?>><?= h($c['COLUMN_NAME']) ?></option><?php }?></select></div><div class="col-md-3"><label class="form-label">Group by</label><select class="form-select" name="group_column"><option value="">None</option><?php foreach($columns as $c){?><option<?= g('group_column')===$c['COLUMN_NAME']?' selected':'' ?>><?= h($c['COLUMN_NAME']) ?></option><?php }?></select></div><div class="col-md-2"><label class="form-label">Rows per page</label><input class="form-control" type="number" name="limit" min="1" max="500" value="<?= h((string)$limit) ?>"></div><div class="col-md-2"><label class="form-label d-block">Display</label><label class="form-check"><input class="form-check-input" type="checkbox" name="show_all" value="1"<?= $showAll?' checked':'' ?>><span class="form-check-label">Show all rows</span></label><div class="form-text">May use substantial memory.</div></div></div><hr><h3 class="h6">Ordering</h3><?php for($i=0;$i<2;$i++){?><div class="row g-2 mb-2"><div class="col-md-4"><select class="form-select" name="order_col[]"><option value="">Column…</option><?php foreach($columns as $c){?><option<?= (($_GET['order_col'][$i]??'')===$c['COLUMN_NAME'])?' selected':'' ?>><?= h($c['COLUMN_NAME']) ?></option><?php }?></select></div><div class="col-md-2"><select class="form-select" name="order_dir[]"><option>ASC</option><option<?= (($_GET['order_dir'][$i]??'')==='DESC')?' selected':'' ?>>DESC</option></select></div></div><?php }?><button class="btn btn-primary">Run query</button> <a class="btn btn-secondary" href="?page=select&amp;table=<?= urlencode($table) ?>">Reset</a></form></div></div></div>
  <?php if(!$showAll){render_select_pagination($page,$pages,'top');} ?>
  <form method="post" id="ms-select-row-form"><input type="hidden" name="return_to" value="<?= h($returnToken) ?>"><?= csrf_field() ?><div class="card"><div class="table-scroll"><table class="table table-sm table-striped table-hover align-middle mb-0 ms-data-table<?= !$aggregated?' ms-layout-table':'' ?>"<?php if(!$aggregated){ ?> data-ms-table-layout data-ms-database="<?= h(selected_db()) ?>" data-ms-table="<?= h($table) ?>" data-ms-columns="<?= h($layoutColumnsJson) ?>" data-ms-layout="<?= h($savedLayoutJson) ?>"<?php } ?>><thead><tr><?php
    if(!$aggregated){if($editable){?><th data-ms-static-column="selection"><input class="form-check-input" type="checkbox" data-check-all=".row-check"></th><?php }?><th class="ms-row-actions-cell" data-ms-static-column="actions" aria-label="Row actions"></th><?php }
    foreach($headers as $header){
      $header=(string)$header;
      $imageRule=is_array($imageColumns[$header]??null)?$imageColumns[$header]:[];
      $softRule=is_array($softFkRules[$header]??null)?$softFkRules[$header]:[];
      $formatRule=is_array($formatRules[$header]??null)?$formatRules[$header]:[];
      $displayLabel=trim((string)($labelRules[$header]??''));$visibleHeader=$displayLabel!==''?$displayLabel:$header;
      $storedImageRule=is_array($storedImageColumns[$header]??null)?$storedImageColumns[$header]:[];
      $storedSoftRule=is_array($storedSoftFkRules[$header]??null)?$storedSoftFkRules[$header]:[];
      $storedFormatRule=is_array($storedFormatRules[$header]??null)?$storedFormatRules[$header]:[];
      $storedDisplayLabel=trim((string)($storedLabelRules[$header]??''));
      ?><th<?php if(!$aggregated){ ?> data-ms-column="<?= h($header) ?>" data-ms-hidden="<?= !empty($storedHiddenColumns[$header]) ? '1' : '0' ?>" data-ms-display-label="<?= h($storedDisplayLabel) ?>" data-ms-display-kind="<?= h((string)($storedFormatRule['kind']??'')) ?>" data-ms-display-format="<?= h((string)($storedFormatRule['format']??'')) ?>" data-ms-money-currency="<?= h((string)($storedFormatRule['currency']??'')) ?>" data-ms-money-decimals="<?= h((string)($storedFormatRule['decimals']??2)) ?>" data-ms-image-base="<?= h((string)($storedImageRule['base_url']??'')) ?>" data-ms-image-width="<?= h((string)($storedImageRule['width']??96)) ?>" data-ms-soft-table="<?= h((string)($storedSoftRule['table']??'')) ?>" data-ms-soft-id="<?= h((string)($storedSoftRule['id_column']??'')) ?>" data-ms-soft-value="<?= h((string)($storedSoftRule['value_column']??'')) ?>"<?php } ?>><?php if(!$aggregated){ ?><span class="ms-col-header-main"><span class="ms-col-drag-handle" draggable="true" data-ms-column-drag-handle title="Drag to move column" aria-label="Drag <?= h($header) ?> to move column"><i class="fa-solid fa-grip-vertical" aria-hidden="true"></i></span><span class="ms-col-header-name" data-ms-column-view tabindex="0" role="button" title="Database field: <?= h($header) ?> · Click for column settings" aria-label="Column settings for <?= h($header) ?>"><?= h($visibleHeader) ?></span></span><span class="ms-col-resizer" data-ms-col-resizer title="Drag to resize"></span><?php } else { ?><?= h($header) ?><?php } ?></th><?php
    }
  ?></tr></thead><tbody><?php
  echo ms_render_select_rows_html($db,$table,$columns,$rows,$editable,$aggregated,$hiddenColumns,$imageColumns,$softFkRules,$softFkMaps,$formatRules,$relations,$returnQuery,$returnToken);
  ?></tbody></table></div><?php if(!$rows){?><div class="p-4 text-center text-body-secondary">No rows.</div><?php }?></div>
  <?php if($editable&&!$aggregated){?><div class="card mt-3 no-print"><div class="card-body"><div class="row g-2 align-items-end"><div class="col-md-auto"><div class="btn-group"><button class="btn btn-danger" name="action" value="delete_rows" data-confirm="Delete the selected rows?">Delete selected</button><button class="btn btn-secondary" name="action" value="clone_selected_prepare"><i class="fa-solid fa-clone me-1"></i>Clone selected</button></div></div><div class="col-md-2"><select class="form-select" name="operation" formaction="<?= h(url()) ?>"><option value="set">Set</option><option value="add">Add number</option><option value="append">Append</option><option value="prepend">Prepend</option><option value="null">Set NULL</option></select></div><div class="col-md-3"><select class="form-select" name="column"><?php foreach($columns as $c){?><option><?= h($c['COLUMN_NAME']) ?></option><?php }?></select></div><div class="col-md-3"><input class="form-control" name="bulk_value" placeholder="Bulk value"></div><div class="col-md-auto"><button class="btn btn-primary" name="action" value="bulk_update">Update selected</button></div></div></div></div><?php }?></form>
  <?php if($hasMoreRows){ ?><div class="d-flex justify-content-center mt-2 no-print" data-ms-show-more data-next-offset="<?= h((string)$nextOffset) ?>" data-total="<?= h((string)$total) ?>">
    <div class="input-group input-group-sm" style="max-width:22rem">
      <button class="btn btn-outline-primary" type="button" data-ms-show-more-button><i class="fa-solid fa-angles-down me-1"></i>Show</button>
      <input class="form-control text-center" type="number" min="1" max="5000" step="1" value="<?= h((string)$moreRowsDefault) ?>" data-ms-show-more-count aria-label="Rows to show">
      <span class="input-group-text">more rows</span>
    </div>
  </div><?php } ?>
  <?php if(!$aggregated){ ?>
  <div class="modal fade" id="ms-column-view-modal" tabindex="-1" aria-hidden="true">
    <div class="modal-dialog modal-lg"><div class="modal-content"><form method="post" id="ms-column-view-form">
      <input type="hidden" name="config_table" value="<?= h($table) ?>"><input type="hidden" name="config_column" value=""><?= csrf_field() ?>
      <div class="modal-header"><h2 class="modal-title fs-5"><i class="fa-solid fa-table-columns me-2"></i>Column display settings</h2><button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button></div>
      <div class="modal-body">
        <div class="mb-3"><div class="small text-body-secondary">Database field</div><div class="fw-semibold code" data-ms-modal-column></div></div>
        <div class="border rounded p-3 mb-3 d-flex flex-wrap justify-content-between align-items-center gap-3">
          <div><div class="fw-semibold"><i class="fa-solid fa-eye-slash me-2"></i>Hide column</div><div class="small text-body-secondary">Hide this field only from the table browse view. The MySQL column is not changed.</div></div>
          <div class="form-check form-switch ms-ios-switch m-0"><input class="form-check-input" type="checkbox" role="switch" id="ms-hide-column" name="hide_column" value="1"><label class="form-check-label" for="ms-hide-column"><span data-ms-hide-label>Visible</span></label></div>
        </div>
        <div class="mb-3"><label class="form-label" for="ms-display-label">Custom field name</label><input class="form-control" id="ms-display-label" name="display_label" maxlength="200" placeholder="Leave blank to use the database field name"><div class="form-text">Display-only alias. It does not rename the MySQL column.</div></div>
        <label class="form-label" for="ms-display-style">Viewing style</label>
        <select class="form-select" id="ms-display-style" name="display_style">
          <option value="default">Default / raw database value</option>
          <option value="date">Date</option>
          <option value="datetime">Date &amp; time</option>
          <option value="money">Money</option>
          <option value="image">Picture from URL prefix + field value</option>
          <option value="soft_fk">Virtual foreign key</option>
        </select>

        <div class="border rounded p-3 mt-3" data-ms-display-section="date" hidden>
          <label class="form-label" for="ms-date-format">Date format</label>
          <select class="form-select" id="ms-date-format" name="date_format">
            <optgroup label="European / day first">
              <option value="d-m-Y">31-08-2026</option>
              <option value="d/m/Y">31/08/2026</option>
              <option value="d.m.Y">31.08.2026</option>
              <option value="j/n/Y">31/8/2026</option>
            </optgroup>
            <optgroup label="ISO / sortable">
              <option value="Y-m-d">2026-08-31</option>
              <option value="Ymd">20260831</option>
            </optgroup>
            <optgroup label="US / month first">
              <option value="m/d/Y">08/31/2026</option>
              <option value="m-d-Y">08-31-2026</option>
            </optgroup>
            <optgroup label="Textual">
              <option value="j M Y">31 Aug 2026</option>
              <option value="j F Y">31 August 2026</option>
              <option value="M j, Y">Aug 31, 2026</option>
              <option value="F j, Y">August 31, 2026</option>
              <option value="D, d M Y">Mon, 31 Aug 2026</option>
              <option value="l, j F Y">Monday, 31 August 2026</option>
            </optgroup>
          </select>
        </div>

        <div class="border rounded p-3 mt-3" data-ms-display-section="datetime" hidden>
          <label class="form-label" for="ms-datetime-format">Date/time format</label>
          <select class="form-select" id="ms-datetime-format" name="datetime_format">
            <optgroup label="European · 24-hour">
              <option value="d-m-Y H:i">31-08-2026 14:35</option>
              <option value="d-m-Y H:i:s">31-08-2026 14:35:52</option>
              <option value="d/m/Y H:i">31/08/2026 14:35</option>
              <option value="d/m/Y H:i:s">31/08/2026 14:35:52</option>
              <option value="d.m.Y H:i">31.08.2026 14:35</option>
              <option value="d.m.Y H:i:s">31.08.2026 14:35:52</option>
              <option value="j/n/Y H:i">31/8/2026 14:35</option>
            </optgroup>
            <optgroup label="ISO / sortable">
              <option value="Y-m-d H:i">2026-08-31 14:35</option>
              <option value="Y-m-d H:i:s">2026-08-31 14:35:52</option>
              <option value="Y-m-d\TH:i">2026-08-31T14:35</option>
              <option value="Y-m-d\TH:i:s">2026-08-31T14:35:52</option>
            </optgroup>
            <optgroup label="US / month first">
              <option value="m/d/Y H:i">08/31/2026 14:35</option>
              <option value="m/d/Y H:i:s">08/31/2026 14:35:52</option>
              <option value="m/d/Y h:i A">08/31/2026 02:35 PM</option>
              <option value="m/d/Y h:i:s A">08/31/2026 02:35:52 PM</option>
            </optgroup>
            <optgroup label="Day first · 12-hour">
              <option value="d/m/Y h:i A">31/08/2026 02:35 PM</option>
              <option value="d/m/Y h:i:s A">31/08/2026 02:35:52 PM</option>
            </optgroup>
            <optgroup label="Textual">
              <option value="j M Y H:i">31 Aug 2026 14:35</option>
              <option value="j F Y H:i">31 August 2026 14:35</option>
              <option value="M j, Y H:i">Aug 31, 2026 14:35</option>
              <option value="M j, Y h:i A">Aug 31, 2026 02:35 PM</option>
              <option value="F j, Y H:i">August 31, 2026 14:35</option>
              <option value="F j, Y h:i A">August 31, 2026 02:35 PM</option>
              <option value="D, d M Y H:i">Mon, 31 Aug 2026 14:35</option>
              <option value="l, j F Y H:i">Monday, 31 August 2026 14:35</option>
            </optgroup>
          </select>
        </div>

        <div class="border rounded p-3 mt-3" data-ms-display-section="money" hidden>
          <div class="row g-3">
            <div class="col-md-7"><label class="form-label" for="ms-money-currency">Currency / prefix</label><select class="form-select" id="ms-money-currency" name="money_currency"><option value="">No currency symbol</option><option value="EUR">€ Euro</option><option value="USD">$ US Dollar</option><option value="THB">฿ Thai Baht</option><option value="GBP">£ British Pound</option></select></div>
            <div class="col-md-5"><label class="form-label" for="ms-money-decimals">Decimal places</label><select class="form-select" id="ms-money-decimals" name="money_decimals"><?php for($i=0;$i<=4;$i++){?><option value="<?= $i ?>"<?= $i===2?' selected':'' ?>><?= $i ?></option><?php }?></select></div>
          </div>
          <div class="form-text mt-2">Thousands are grouped with commas and decimals use a dot, for example <code>฿ 12,345.67</code>.</div>
        </div>

        <div class="border rounded p-3 mt-3" data-ms-display-section="image" hidden>
          <label class="form-label" for="ms-image-base-url">URL prefix</label><input class="form-control code" id="ms-image-base-url" name="image_base_url" placeholder="https://example.com/images/">
          <div class="form-text">The field content is appended exactly. Example: <code>https://site/images/</code> + <code>123.jpg</code>. The thumbnail is clickable and opens the full picture.</div>
          <label class="form-label mt-3" for="ms-image-width">Thumbnail width</label><div class="input-group"><input class="form-control" type="number" id="ms-image-width" name="image_width" min="16" max="1024" value="96"><span class="input-group-text">px</span></div>
        </div>

        <div class="border rounded p-3 mt-3" data-ms-display-section="soft_fk" hidden>
          <p class="text-body-secondary small mb-3">Display this field through another table without creating a real MySQL constraint. The displayed value remains clickable and opens the matching target row.</p>
          <label class="form-label" for="ms-soft-fk-table">Target table / view</label><select class="form-select" id="ms-soft-fk-table" name="soft_fk_table"><option value="">Choose…</option><?php foreach($softTargetTables as $targetTable){?><option value="<?= h($targetTable) ?>"><?= h($targetTable) ?></option><?php }?></select>
          <div class="row g-3 mt-1"><div class="col-md-6"><label class="form-label" for="ms-soft-fk-id">Target ID column</label><select class="form-select" id="ms-soft-fk-id" name="soft_fk_id_column" disabled><option value="">Choose table first…</option></select></div><div class="col-md-6"><label class="form-label" for="ms-soft-fk-value">Field to display</label><select class="form-select" id="ms-soft-fk-value" name="soft_fk_value_column" disabled><option value="">Choose table first…</option></select></div></div>
          <div class="alert alert-warning mt-3 mb-0 small"><i class="fa-solid fa-triangle-exclamation me-1"></i>This is display-only. MySQL referential integrity is not changed.</div>
        </div>
      </div>
      <div class="modal-footer justify-content-between"><button class="btn btn-outline-danger" type="submit" name="action" value="column_view_display_clear" data-confirm="Reset this column to its default display name, raw value, and visible state?"><i class="fa-solid fa-eraser me-1"></i>Reset to default</button><div><button class="btn btn-secondary" type="button" data-bs-dismiss="modal">Cancel</button> <button class="btn btn-primary" type="submit" name="action" value="column_view_display_save"><i class="fa-solid fa-floppy-disk me-1"></i>Save</button></div></div>
    </form></div></div>
  </div>
  <script>
  document.addEventListener('DOMContentLoaded',()=>{
    'use strict';
    const viewForm=document.getElementById('ms-column-view-form');
    const viewModal=document.getElementById('ms-column-view-modal');
    const displayStyle=document.getElementById('ms-display-style');
    const displayLabel=document.getElementById('ms-display-label');
    const hideColumn=document.getElementById('ms-hide-column');
    const hideLabel=document.querySelector('[data-ms-hide-label]');
    const dateFormat=document.getElementById('ms-date-format');
    const datetimeFormat=document.getElementById('ms-datetime-format');
    const moneyCurrency=document.getElementById('ms-money-currency');
    const moneyDecimals=document.getElementById('ms-money-decimals');
    const imageBase=document.getElementById('ms-image-base-url');
    const imageWidth=document.getElementById('ms-image-width');
    const softTable=document.getElementById('ms-soft-fk-table');
    const softId=document.getElementById('ms-soft-fk-id');
    const softValue=document.getElementById('ms-soft-fk-value');
    const sections=Array.from(viewModal.querySelectorAll('[data-ms-display-section]'));
    let currentHeader=null;
    const setColumnLabels=column=>viewModal.querySelectorAll('[data-ms-modal-column]').forEach(el=>el.textContent=column);
    const fillColumnSelect=(select,columns,selected)=>{select.innerHTML='<option value="">Choose…</option>';columns.forEach(column=>{const option=document.createElement('option');option.value=column;option.textContent=column;if(column===selected)option.selected=true;select.appendChild(option);});select.disabled=false;};
    const loadSoftColumns=async(table,idSelected='',valueSelected='')=>{
      softId.disabled=true;softValue.disabled=true;
      if(!table){softId.innerHTML='<option value="">Choose table first…</option>';softValue.innerHTML='<option value="">Choose table first…</option>';return;}
      softId.innerHTML='<option>Loading…</option>';softValue.innerHTML='<option>Loading…</option>';
      try{
        const response=await fetch(`?ajax=soft_fk_columns&table=${encodeURIComponent(table)}`,{credentials:'same-origin',headers:{'Accept':'application/json'}});
        const data=await response.json();if(!response.ok||!data.ok)throw new Error(data.error||'Unable to load columns.');
        const columns=data.columns||[];
        const defaultId=idSelected!==''?idSelected:(columns.includes('id')?'id':'');
        fillColumnSelect(softId,columns,defaultId);fillColumnSelect(softValue,columns,valueSelected);
      }catch(error){softId.innerHTML='<option value="">Unable to load</option>';softValue.innerHTML='<option value="">Unable to load</option>';softId.disabled=true;softValue.disabled=true;alert(error.message||'Unable to load target columns.');}
    };
    const updateSections=()=>{
      const style=displayStyle.value;
      sections.forEach(section=>section.hidden=section.dataset.msDisplaySection!==style);
    };
    const updateHideLabel=()=>{if(hideLabel)hideLabel.textContent=hideColumn&&hideColumn.checked?'Hidden':'Visible';};
    const openViewSettings=async header=>{
      if(!header)return;
      currentHeader=header;
      const column=header.dataset.msColumn||'';
      viewForm.elements.config_column.value=column;setColumnLabels(column);
      displayLabel.value=header.dataset.msDisplayLabel||'';
      hideColumn.checked=header.dataset.msHidden==='1';updateHideLabel();
      let style=header.dataset.msDisplayKind||'';
      if(header.dataset.msImageBase)style='image';
      else if(header.dataset.msSoftTable)style='soft_fk';
      else if(!['date','datetime','money'].includes(style))style='default';
      displayStyle.value=style;
      dateFormat.value=style==='date'&&(header.dataset.msDisplayFormat||'')?header.dataset.msDisplayFormat:'d-m-Y';
      datetimeFormat.value=style==='datetime'&&(header.dataset.msDisplayFormat||'')?header.dataset.msDisplayFormat:'d-m-Y H:i:s';
      moneyCurrency.value=header.dataset.msMoneyCurrency||'';
      moneyDecimals.value=header.dataset.msMoneyDecimals||'2';
      imageBase.value=header.dataset.msImageBase||'';imageWidth.value=header.dataset.msImageWidth||'96';
      const target=header.dataset.msSoftTable||'',id=header.dataset.msSoftId||'',value=header.dataset.msSoftValue||'';
      softTable.value=target;softId.dataset.selected=id;softValue.dataset.selected=value;
      if(style!=='soft_fk'){softId.innerHTML='<option value="">Choose table first…</option>';softValue.innerHTML='<option value="">Choose table first…</option>';softId.disabled=true;softValue.disabled=true;}
      updateSections();
      bootstrap.Modal.getOrCreateInstance(viewModal).show();
      if(style==='soft_fk')await loadSoftColumns(target,id,value);
      setTimeout(()=>displayStyle.focus(),150);
    };
    document.querySelectorAll('[data-ms-column-view]').forEach(trigger=>{
      const open=event=>{event.preventDefault();event.stopPropagation();openViewSettings(trigger.closest('th[data-ms-column]'));};
      trigger.addEventListener('click',open);
      trigger.addEventListener('keydown',event=>{if(event.key==='Enter'||event.key===' '){open(event);}});
    });
    hideColumn.addEventListener('change',updateHideLabel);
    displayStyle.addEventListener('change',()=>{updateSections();if(displayStyle.value==='soft_fk')loadSoftColumns(softTable.value,softId.dataset.selected||'',softValue.dataset.selected||'');});
    softTable.addEventListener('change',()=>{softId.dataset.selected='';softValue.dataset.selected='';loadSoftColumns(softTable.value);});
  });
  </script>
  <?php } ?>
  <script>
  (()=>{
    'use strict';
    const wrap=document.querySelector('[data-ms-show-more]');
    if(!wrap)return;
    const button=wrap.querySelector('[data-ms-show-more-button]');
    const input=wrap.querySelector('[data-ms-show-more-count]');
    const table=document.querySelector('#ms-select-row-form .ms-data-table');
    const tbody=table?table.querySelector('tbody'):null;
    if(!button||!input||!table||!tbody)return;
    let nextOffset=Math.max(0,Number.parseInt(wrap.dataset.nextOffset||'0',10)||0);
    const total=Math.max(0,Number.parseInt(wrap.dataset.total||'0',10)||0);
    const applyCurrentLayout=rows=>{
      const headerMap=new Map(Array.from(table.querySelectorAll('thead th[data-ms-column]')).map(th=>[th.dataset.msColumn||'',th]));
      const headerColumns=Array.from(headerMap.keys()).filter(Boolean);
      rows.forEach(row=>{
        const cells=new Map(Array.from(row.children).filter(cell=>cell.dataset&&cell.dataset.msColumn).map(cell=>[cell.dataset.msColumn,cell]));
        headerColumns.forEach(column=>{const cell=cells.get(column);if(cell)row.appendChild(cell);});
        headerColumns.forEach(column=>{
          const header=headerMap.get(column);
          const cell=cells.get(column);
          if(!header||!cell)return;
          if(header.style.width)cell.style.width=header.style.width;
          if(header.style.minWidth)cell.style.minWidth=header.style.minWidth;
          if(header.style.maxWidth)cell.style.maxWidth=header.style.maxWidth;
        });
      });
    };
    button.addEventListener('click',async()=>{
      let count=Number.parseInt(input.value,10);
      if(!Number.isFinite(count))count=1;
      count=Math.max(1,Math.min(5000,count));
      input.value=String(count);
      const original=button.innerHTML;
      button.disabled=true;input.disabled=true;
      button.innerHTML='<i class="fa-solid fa-spinner fa-spin me-1"></i>Loading';
      try{
        const destination=new URL(window.location.href);
        destination.searchParams.set('ajax','select_more');
        destination.searchParams.set('offset',String(nextOffset));
        destination.searchParams.set('count',String(count));
        destination.searchParams.delete('single_id');
        const response=await fetch(destination.toString(),{credentials:'same-origin',headers:{'Accept':'application/json'}});
        const data=await response.json();
        if(!response.ok||!data.ok)throw new Error(data.error||'Unable to load more rows.');
        const holder=document.createElement('tbody');
        holder.innerHTML=String(data.html||'');
        const newRows=Array.from(holder.children);
        newRows.forEach(row=>tbody.appendChild(row));
        applyCurrentLayout(newRows);
        nextOffset=Math.max(nextOffset,Number.parseInt(data.next_offset,10)||nextOffset);
        wrap.dataset.nextOffset=String(nextOffset);
        if(!data.has_more||!newRows.length)wrap.remove();
      }catch(error){
        if(window.Swal&&typeof window.Swal.fire==='function')window.Swal.fire({icon:'error',title:'Unable to show more rows',text:error.message||'The additional rows could not be loaded.'});
        else alert(error.message||'Unable to show more rows.');
      }finally{
        if(document.body.contains(button)){button.disabled=false;input.disabled=false;button.innerHTML=original;}
      }
    });
  })();
  </script>
  <?php if($showAll){?><div class="alert alert-info mt-3 mb-0 no-print"><i class="fa-solid fa-list me-1"></i>All <?= h(number_format($total)) ?> result(s) are displayed. <a href="<?= h(url(['show_all'=>null,'p'=>null,'limit'=>null])) ?>">Return to paginated view</a>.</div><?php }else{render_select_pagination($page,$pages,'bottom');}?><div class="small text-body-secondary code mt-2">Query: <?= h($sql) ?></div><?php
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
  $tableMeta = db_one($db, 'SELECT TABLE_TYPE FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=' . qs($db, $table));
  $isBaseTable = ($tableMeta['TABLE_TYPE'] ?? '') === 'BASE TABLE';
  $mode = g('mode', 'insert');
  if (!in_array($mode, ['insert','edit','view','clone'], true)) {
    $mode = 'insert';
  }
  $returnQuery = ms_decode_navigation(g('return_to'));
  if (($returnQuery['page'] ?? '') !== 'select' || ($returnQuery['table'] ?? '') !== $table) {
    $returnQuery = ['page' => 'select', 'table' => $table];
  }
  $returnToken = ms_encode_navigation($returnQuery);
  $returnUrl = '?' . http_build_query($returnQuery);
  $identity = null;
  $sourceIdentity = null;
  $values = [];
  if (in_array($mode, ['edit','view','clone'], true)) {
    $sourceIdentity = decode_identity(g('id'));
    if (!is_array($sourceIdentity)) {
      throw new RuntimeException('Invalid row identity.');
    }
    $values = db_one($db, 'SELECT * FROM ' . qi($table) . ' WHERE ' . row_identity_where($db, $columns, $sourceIdentity) . ' LIMIT 1') ?? [];
    if (!$values) {
      throw new RuntimeException('Row not found.');
    }
    if ($mode === 'edit') {
      if (!$isBaseTable) {
        throw new RuntimeException('This view is not directly editable.');
      }
      $identity = $sourceIdentity;
    } elseif ($mode === 'clone') {
      if (!$isBaseTable) {
        throw new RuntimeException('This view cannot be cloned as a table row.');
      }
      foreach ($columns as $column) {
        if (strpos((string)$column['EXTRA'], 'auto_increment') !== false) {
          $values[$column['COLUMN_NAME']] = '';
        }
      }
    }
  } elseif (!empty($_SESSION['ms_clone'])) {
    $values = $_SESSION['ms_clone'];
    unset($_SESSION['ms_clone']);
    foreach ($columns as $column) {
      if (strpos((string)$column['EXTRA'], 'auto_increment') !== false) {
        $values[$column['COLUMN_NAME']] = '';
      }
    }
  }

  if ($mode === 'view') {
    $emptyViewConfig = ['hidden'=>[],'images'=>[],'soft_fk'=>[],'formats'=>[],'labels'=>[]];
    $storedViewConfig = ms_column_view_table_config(selected_db(), $table);
    $viewConfig = ms_raw_db_view() ? $emptyViewConfig : $storedViewConfig;
    $hiddenColumns = is_array($viewConfig['hidden'] ?? null) ? $viewConfig['hidden'] : [];
    $imageColumns = is_array($viewConfig['images'] ?? null) ? $viewConfig['images'] : [];
    $softFkRules = is_array($viewConfig['soft_fk'] ?? null) ? $viewConfig['soft_fk'] : [];
    $formatRules = is_array($viewConfig['formats'] ?? null) ? $viewConfig['formats'] : [];
    $labelRules = is_array($viewConfig['labels'] ?? null) ? $viewConfig['labels'] : [];
    $softFkMaps = ms_soft_fk_maps($db, [$values], $softFkRules);
    $relations = [];
    foreach (db_all($db, "SELECT COLUMN_NAME,REFERENCED_TABLE_NAME,REFERENCED_COLUMN_NAME FROM information_schema.KEY_COLUMN_USAGE WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=" . qs($db,$table) . " AND REFERENCED_TABLE_NAME IS NOT NULL") as $relation) {
      $relations[$relation['COLUMN_NAME']] = $relation;
    }
    $encoded = encode_identity($sourceIdentity);
    $actions = '<a class="btn btn-secondary" href="' . h($returnUrl) . '"><i class="fa-solid fa-arrow-left me-1"></i>Back</a>';
    if ($isBaseTable) {
      $actions .= ' <a class="btn btn-primary" href="?' . h(http_build_query(['page'=>'row','mode'=>'edit','table'=>$table,'id'=>$encoded,'return_to'=>$returnToken])) . '"><i class="fa-solid fa-pen me-1"></i>Edit</a>';
      $actions .= ' <a class="btn btn-secondary" href="?' . h(http_build_query(['page'=>'row','mode'=>'clone','table'=>$table,'id'=>$encoded,'return_to'=>$returnToken])) . '"><i class="fa-solid fa-clone me-1"></i>Clone</a>';
    }
    title_bar('View row: ' . $table, ms_raw_db_view() ? 'Raw database values are being shown.' : 'Saved column viewing rules are applied.', $actions);
    ?><div class="card"><div class="table-responsive"><table class="table table-sm align-middle mb-0"><thead><tr><th style="width:24%">Field</th><th>Value</th><th style="width:18%">Type</th></tr></thead><tbody><?php
    $shown = 0;
    foreach ($columns as $column) {
      $name = (string)$column['COLUMN_NAME'];
      if (!empty($hiddenColumns[$name])) continue;
      $shown++;
      $value = $values[$name] ?? null;
      $customLabel = trim((string)($labelRules[$name] ?? ''));
      $visibleLabel = $customLabel !== '' ? $customLabel : $name;
      ?><tr><th><div><?= h($visibleLabel) ?></div><?php if ($customLabel !== '') { ?><div class="small text-body-secondary code"><?= h($name) ?></div><?php } ?></th><td><?php
      if (isset($formatRules[$name]) && is_array($formatRules[$name])) {
        echo ms_render_formatted_value($value, $formatRules[$name]);
      } elseif (isset($imageColumns[$name]) && is_array($imageColumns[$name])) {
        echo ms_render_image_value($value, $imageColumns[$name]);
      } elseif (isset($softFkRules[$name]) && is_array($softFkRules[$name]) && $value !== null) {
        $soft = $softFkRules[$name];
        $map = $softFkMaps[$name] ?? [];
        $key = (string)$value;
        $found = array_key_exists($key, $map);
        $display = $found ? $map[$key] : $value;
        $relUrl = '?' . http_build_query(['page'=>'select','table'=>(string)($soft['table']??''),'filter_col'=>[(string)($soft['id_column']??'')],'filter_op'=>['='],'filter_val'=>[(string)$value]]);
        ?><a href="<?= h($relUrl) ?>" title="Virtual foreign key: <?= h($name) ?> = <?= h((string)$value) ?>"><?= render_value($display, MS_MAX_CELL_BYTES) ?> <i class="fa-solid <?= $found?'fa-link':'fa-link-slash' ?> small"></i></a><?php
      } elseif (preg_match('/blob|binary/i', (string)$column['DATA_TYPE']) && $value !== null) {
        ?><a href="?download=blob&amp;table=<?= urlencode($table) ?>&amp;column=<?= urlencode($name) ?>&amp;id=<?= urlencode($encoded) ?>"><i class="fa-solid fa-download me-1"></i><?= h(strlen((string)$value)) ?> bytes</a><?php
      } elseif (isset($relations[$name]) && $value !== null) {
        $rel = $relations[$name];
        $relUrl = '?' . http_build_query(['page'=>'select','table'=>$rel['REFERENCED_TABLE_NAME'],'filter_col'=>[$rel['REFERENCED_COLUMN_NAME']],'filter_op'=>['='],'filter_val'=>[(string)$value]]);
        ?><a href="<?= h($relUrl) ?>" title="Open referenced row"><?= render_value($value, MS_MAX_CELL_BYTES) ?> <i class="fa-solid fa-arrow-up-right-from-square small"></i></a><?php
      } else {
        echo render_value($value, MS_MAX_CELL_BYTES);
      }
      ?></td><td class="code small text-body-secondary"><?= h((string)$column['COLUMN_TYPE']) ?></td></tr><?php
    }
    if ($shown === 0) { ?><tr><td colspan="3" class="text-center text-body-secondary p-4">Every column is hidden by the current viewing rules. Enable Raw DB view to see the complete row.</td></tr><?php }
    ?></tbody></table></div></div><?php
    return;
  }

  $titleVerb = $mode === 'edit' ? 'Edit' : ($mode === 'clone' ? 'Clone' : 'Insert');
  $subtitle = $mode === 'clone'
    ? 'Review the copied values before creating the new row. Auto-increment fields are cleared.'
    : 'Literal values are validated according to their MySQL type. Enable SQL expression to enter raw SQL.';
  title_bar($titleVerb . ' row: ' . $table, $subtitle);
  ?><form method="post" enctype="multipart/form-data" data-ms-row-form>
    <input type="hidden" name="action" value="save_row">
    <input type="hidden" name="identity" value="<?= h($identity === null ? '' : encode_identity($identity)) ?>">
    <?php if ($mode === 'clone' && is_array($sourceIdentity)) { ?><input type="hidden" name="clone_source" value="<?= h(encode_identity($sourceIdentity)) ?>"><?php } ?>
    <input type="hidden" name="return_to" value="<?= h($returnToken) ?>">
    <?= csrf_field() ?>
    <div class="card"><div class="table-responsive"><table class="table align-middle mb-0"><thead><tr><th>Column</th><th>Type</th><th>Value</th><th>Options</th></tr></thead><tbody>
    <?php foreach ($columns as $column) {
      $name = (string)$column['COLUMN_NAME'];
      $generated = strpos((string)$column['EXTRA'], 'GENERATED') !== false;
      $binary = preg_match('/blob|binary/i', (string)$column['DATA_TYPE']) === 1;
      $spec = ms_column_edit_spec($column);
      $currentIsNull = in_array($mode, ['edit','clone'], true) && array_key_exists($name, $values) && $values[$name] === null;
      ?><tr data-ms-field-row><td><strong><?= h($name) ?></strong><?php if ($column['COLUMN_KEY']) { ?><span class="badge text-bg-primary ms-1"><?= h($column['COLUMN_KEY']) ?></span><?php } ?></td><td class="code small"><?= h($column['COLUMN_TYPE']) ?></td><td>
      <?php if ($generated) { ?>
        <span class="text-body-secondary">Generated automatically</span>
      <?php } elseif ($binary) { ?>
        <?php if (in_array($mode, ['edit','clone'], true) && array_key_exists($name, $values) && $values[$name] !== null) { ?><div class="small mb-1"><?= h(strlen((string)$values[$name])) ?> existing bytes</div><?php } ?>
        <input class="form-control mb-1" type="file" name="upload[<?= h($name) ?>]">
        <textarea class="form-control code" name="value[<?= h($name) ?>]" rows="2" placeholder="Or enter textual bytes"></textarea>
      <?php } elseif (in_array($column['DATA_TYPE'], ['text','mediumtext','longtext'], true)) { ?>
        <textarea class="form-control code" name="value[<?= h($name) ?>]" rows="4"><?= h($values[$name] ?? '') ?></textarea>
      <?php } elseif ($column['DATA_TYPE'] === 'json') { ?>
        <textarea class="form-control code" name="value[<?= h($name) ?>]" rows="6"<?= ms_smart_input_attributes($spec) ?>><?= h($values[$name] ?? '') ?></textarea>
        <div class="form-text"><?= h($spec['help']) ?></div>
      <?php } elseif ($column['DATA_TYPE'] === 'enum' && preg_match_all("/'((?:[^'\\\\]|\\\\.)*)'/", (string)$column['COLUMN_TYPE'], $matches)) { ?>
        <select class="form-select" name="value[<?= h($name) ?>]"><?php foreach ($matches[1] as $option) { $option = stripcslashes($option); ?><option<?= (($values[$name] ?? '') === $option) ? ' selected' : '' ?>><?= h($option) ?></option><?php } ?></select>
      <?php } else { ?>
        <?php if (in_array($spec['kind'], ['date','datetime'], true)) { $pickerType = $spec['kind'] === 'date' ? 'date' : 'datetime-local'; ?>
          <div class="input-group ms-date-editor" data-ms-date-editor data-ms-picker-kind="<?= h($spec['kind']) ?>">
            <input class="form-control code ms-manual-input" name="value[<?= h($name) ?>]" value="<?= h($values[$name] ?? '') ?>"<?= ms_smart_input_attributes($spec) ?> data-ms-manual-input>
            <input class="form-control code ms-picker-input" type="<?= h($pickerType) ?>"<?= $spec['kind'] === 'datetime' ? ' step="1"' : '' ?> data-ms-picker-input hidden>
            <button class="btn btn-outline-secondary ms-picker-toggle" type="button" data-ms-picker-toggle title="Switch to date picker" aria-label="Switch to date picker"><i class="fa-solid fa-calendar-days"></i></button>
          </div>
        <?php } else { ?>
          <input class="form-control<?= in_array($spec['kind'], ['integer','decimal','float','time','year'], true) ? ' code' : '' ?>" name="value[<?= h($name) ?>]" value="<?= h($values[$name] ?? '') ?>"<?= ms_smart_input_attributes($spec) ?>>
        <?php } ?>
        <?php if ($spec['help'] !== '') { ?><div class="form-text"><?= h($spec['help']) ?><?= in_array($spec['kind'], ['date','datetime'], true) ? ' · switch between typing and the native picker' : '' ?></div><?php } ?>
      <?php } ?></td><td><?php if (!$generated) { ?>
        <label class="d-block"><input class="form-check-input" type="checkbox" name="is_null[<?= h($name) ?>]" data-ms-null<?= $currentIsNull ? ' checked' : '' ?>> NULL</label>
        <label class="d-block"><input class="form-check-input" type="checkbox" name="expression[<?= h($name) ?>]" data-ms-expression> SQL expression</label>
        <?php if ($binary && in_array($mode, ['edit','clone'], true)) { ?><label class="d-block"><input class="form-check-input" type="checkbox" name="keep_blob[<?= h($name) ?>]" checked> <?= $mode === 'clone' ? 'Copy existing BLOB' : 'Keep existing' ?></label><?php } ?>
      <?php } ?></td></tr>
    <?php } ?>
    </tbody></table></div></div>
    <div class="mt-3 d-flex gap-2"><button class="btn btn-primary">Save row</button><a class="btn btn-secondary" href="<?= h($returnUrl) ?>">Cancel</a></div>
  </form>
  <script>
  (() => {
    'use strict';

    const form = document.querySelector('[data-ms-row-form]');
    if (!form) return;

    const compareUnsignedDecimal = (a, b) => {
      a = String(a || '').replace(/^0+/, '') || '0';
      b = String(b || '').replace(/^0+/, '') || '0';
      if (a.length !== b.length) return a.length < b.length ? -1 : 1;
      return a === b ? 0 : (a < b ? -1 : 1);
    };

    const normalizeInteger = (value, unsigned) => {
      let source = String(value || '');
      const negative = !unsigned && source.startsWith('-');
      source = source.replace(/\D/g, '');
      source = source.replace(/^0+(?=\d)/, '');
      if (source === '') return negative ? '-' : '';
      if (/^0+$/.test(source)) return '0';
      return (negative ? '-' : '') + source;
    };

    const normalizeDecimal = (value, unsigned) => {
      let source = String(value || '').replace(/,/g, '.');
      const negative = !unsigned && source.startsWith('-');
      source = source.replace(/[^\d.]/g, '');
      const dot = source.indexOf('.');
      if (dot !== -1) {
        source = source.slice(0, dot + 1) + source.slice(dot + 1).replace(/\./g, '');
      }
      let [integer = '', fraction] = source.split('.', 2);
      integer = integer.replace(/^0+(?=\d)/, '');
      if (source.startsWith('.')) integer = '0';
      const hasDot = source.includes('.');
      let result = (negative ? '-' : '') + integer;
      if (hasDot) result += '.' + (fraction ?? '');
      if (result === '-0' || result === '-0.') return result;
      return result;
    };

    const normalizeFloat = (value, unsigned) => {
      const source = String(value || '').replace(/,/g, '.');
      let out = '';
      let mantissaDigit = false;
      let dotSeen = false;
      let exponentSeen = false;
      let exponentDigit = false;
      for (const char of source) {
        if (/\d/.test(char)) {
          out += char;
          if (exponentSeen) exponentDigit = true;
          else mantissaDigit = true;
          continue;
        }
        if (char === '.' && !dotSeen && !exponentSeen) {
          if (!mantissaDigit) {
            if (out === '-') out += '0';
            else if (out === '') out = '0';
          }
          out += '.';
          dotSeen = true;
          continue;
        }
        if ((char === 'e' || char === 'E') && mantissaDigit && !exponentSeen) {
          out += 'e';
          exponentSeen = true;
          continue;
        }
        if (char === '-' && out === '' && !unsigned) {
          out = '-';
          continue;
        }
        if ((char === '-' || char === '+') && exponentSeen && /e$/i.test(out)) {
          out += char;
        }
      }

      const eIndex = out.search(/e/i);
      const mantissaWithSign = eIndex === -1 ? out : out.slice(0, eIndex);
      const exponent = eIndex === -1 ? '' : out.slice(eIndex);
      const negative = mantissaWithSign.startsWith('-');
      let mantissa = negative ? mantissaWithSign.slice(1) : mantissaWithSign;
      if (mantissa.includes('.')) {
        const parts = mantissa.split('.', 2);
        let integer = parts[0].replace(/^0+(?=\d)/, '');
        if (integer === '') integer = '0';
        mantissa = integer + '.' + parts[1];
      } else {
        mantissa = mantissa.replace(/^0+(?=\d)/, '');
      }
      return (negative ? '-' : '') + mantissa + exponent;
    };

    const sanitize = input => {
      const kind = input.dataset.msKind || 'text';
      const unsigned = input.dataset.msUnsigned === '1';
      if (kind === 'integer') return normalizeInteger(input.value, unsigned);
      if (kind === 'decimal') return normalizeDecimal(input.value, unsigned);
      if (kind === 'float') return normalizeFloat(input.value, unsigned);
      if (kind === 'year') return input.value.replace(/\D/g, '').slice(0, 4);
      if (kind === 'date') return input.value.replace(/[^\d-]/g, '');
      if (kind === 'datetime') return input.value.replace(/[^\dTt :.\-]/g, '').replace(/t/g, 'T');
      if (kind === 'time') {
        let source = input.value.replace(/[^\d:.\-]/g, '');
        const negative = source.startsWith('-');
        source = source.replace(/-/g, '');
        return (negative ? '-' : '') + source;
      }
      return input.value;
    };

    const fieldControls = input => {
      const row = input.closest('[data-ms-field-row]');
      return {
        row,
        nullToggle: row ? row.querySelector('[data-ms-null]') : null,
        expressionToggle: row ? row.querySelector('[data-ms-expression]') : null
      };
    };

    const rawMode = input => {
      const controls = fieldControls(input);
      return !!(controls.expressionToggle && controls.expressionToggle.checked);
    };

    const nullMode = input => {
      const controls = fieldControls(input);
      return !!(controls.nullToggle && controls.nullToggle.checked);
    };

    const validate = input => {
      input.setCustomValidity('');
      if (input.disabled || rawMode(input) || nullMode(input)) return true;

      const value = input.value.trim();
      const kind = input.dataset.msKind || 'text';
      const unsigned = input.dataset.msUnsigned === '1';
      if (value === '') return true;

      if (kind === 'integer') {
        if (!/^-?\d+$/.test(value)) {
          input.setCustomValidity('Enter a whole number.');
          return false;
        }
        if (unsigned && value.startsWith('-')) {
          input.setCustomValidity('This column is UNSIGNED and cannot be negative.');
          return false;
        }
        const negative = value.startsWith('-');
        const digits = (negative ? value.slice(1) : value).replace(/^0+/, '') || '0';
        const min = input.dataset.msMin || '';
        const max = input.dataset.msMax || '';
        if (negative && min && compareUnsignedDecimal(digits, min.replace(/^-/, '')) > 0) {
          input.setCustomValidity('Minimum value: ' + min);
          return false;
        }
        if (!negative && max && compareUnsignedDecimal(digits, max) > 0) {
          input.setCustomValidity('Maximum value: ' + max);
          return false;
        }
      } else if (kind === 'decimal') {
        if (!/^-?(?:(?:\d+(?:\.\d*)?)|(?:\.\d+))$/.test(value)) {
          input.setCustomValidity('Enter a valid decimal number.');
          return false;
        }
        if (unsigned && value.startsWith('-')) {
          input.setCustomValidity('This column is UNSIGNED and cannot be negative.');
          return false;
        }
        const precision = Number.parseInt(input.dataset.msPrecision || '0', 10);
        const scale = Number.parseInt(input.dataset.msScale || '0', 10);
        if (precision > 0) {
          const unsignedValue = value.replace(/^-/, '');
          const [integer = '', fraction = ''] = unsignedValue.split('.', 2);
          const integerDigits = (integer.replace(/^0+/, '') || '').length;
          if (integerDigits > Math.max(0, precision - scale)) {
            input.setCustomValidity('Too many digits before the decimal point.');
            return false;
          }
          if (fraction.length > scale) {
            input.setCustomValidity('Maximum ' + scale + ' decimal place(s).');
            return false;
          }
        }
      } else if (kind === 'float') {
        if (!/^-?(?:(?:\d+(?:\.\d*)?)|(?:\.\d+))(?:[eE][+-]?\d+)?$/.test(value)) {
          input.setCustomValidity('Enter a valid floating-point number.');
          return false;
        }
        if (unsigned && value.startsWith('-')) {
          input.setCustomValidity('This column is UNSIGNED and cannot be negative.');
          return false;
        }
      } else if (kind === 'date' && !/^\d{4}-\d{2}-\d{2}$/.test(value)) {
        input.setCustomValidity('Use YYYY-MM-DD.');
        return false;
      } else if (kind === 'datetime' && !/^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?$/.test(value)) {
        input.setCustomValidity('Use YYYY-MM-DD HH:MM:SS.');
        return false;
      } else if (kind === 'time' && !/^-?\d{1,3}:\d{2}:\d{2}(?:\.\d{1,6})?$/.test(value)) {
        input.setCustomValidity('Use HH:MM:SS.');
        return false;
      } else if (kind === 'year' && !/^\d{1,4}$/.test(value)) {
        input.setCustomValidity('Enter a year using digits only.');
        return false;
      } else if (kind === 'json') {
        try {
          JSON.parse(input.value);
        } catch (error) {
          input.setCustomValidity('Invalid JSON: ' + error.message);
          return false;
        }
      }
      return true;
    };

    const pickerValueFromManual = (manual, kind) => {
      const value = manual.value.trim();
      if (kind === 'date') return /^\d{4}-\d{2}-\d{2}$/.test(value) ? value : '';
      if (kind === 'datetime') {
        const match = value.match(/^(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2})(?::(\d{2}))?(?:\.\d{1,6})?$/);
        if (!match) return '';
        return match[1] + 'T' + match[2] + ':' + (match[3] || '00');
      }
      return '';
    };

    const manualValueFromPicker = (picker, kind) => {
      const value = picker.value.trim();
      if (kind === 'date') return value;
      if (kind === 'datetime') {
        if (value === '') return '';
        const normalized = value.replace('T', ' ');
        return /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}$/.test(normalized) ? normalized + ':00' : normalized;
      }
      return value;
    };

    const setPickerMode = (row, usePicker, openPicker = false) => {
      const editor = row.querySelector('[data-ms-date-editor]');
      if (!editor) return;
      const manual = editor.querySelector('[data-ms-manual-input]');
      const picker = editor.querySelector('[data-ms-picker-input]');
      const toggle = editor.querySelector('[data-ms-picker-toggle]');
      if (!manual || !picker || !toggle) return;
      const kind = editor.dataset.msPickerKind || 'date';
      const expressionToggle = row.querySelector('[data-ms-expression]');
      const nullToggle = row.querySelector('[data-ms-null]');
      if ((expressionToggle && expressionToggle.checked) || (nullToggle && nullToggle.checked)) usePicker = false;
      if (usePicker) {
        const converted = pickerValueFromManual(manual, kind);
        if (converted !== '') picker.value = converted;
      }
      manual.hidden = usePicker;
      picker.hidden = !usePicker;
      editor.dataset.msPickerMode = usePicker ? 'picker' : 'manual';
      toggle.title = usePicker ? 'Switch to typing' : 'Switch to date picker';
      toggle.setAttribute('aria-label', toggle.title);
      const icon = toggle.querySelector('i');
      if (icon) icon.className = usePicker ? 'fa-solid fa-keyboard' : 'fa-solid fa-calendar-days';
      if (usePicker) {
        picker.focus();
        if (openPicker && typeof picker.showPicker === 'function') {
          try { picker.showPicker(); } catch (error) {}
        }
      } else if (openPicker) {
        manual.focus();
      }
    };

    form.querySelectorAll('[data-ms-date-editor]').forEach(editor => {
      const row = editor.closest('[data-ms-field-row]');
      const picker = editor.querySelector('[data-ms-picker-input]');
      const toggle = editor.querySelector('[data-ms-picker-toggle]');
      if (!row || !picker || !toggle) return;
      const kind = editor.dataset.msPickerKind || 'date';
      toggle.addEventListener('click', () => setPickerMode(row, editor.dataset.msPickerMode !== 'picker', true));
      const syncFromPicker = () => {
        const manual = editor.querySelector('[data-ms-manual-input]');
        if (!manual) return;
        manual.value = manualValueFromPicker(picker, kind);
        manual.setCustomValidity('');
      };
      picker.addEventListener('input', syncFromPicker);
      picker.addEventListener('change', syncFromPicker);
      setPickerMode(row, false);
    });

    const syncField = row => {
      const input = row.querySelector('[data-ms-smart-input]');
      if (!input) return;
      const nullToggle = row.querySelector('[data-ms-null]');
      const expressionToggle = row.querySelector('[data-ms-expression]');
      const isNull = !!(nullToggle && nullToggle.checked);
      const isExpression = !!(expressionToggle && expressionToggle.checked);
      input.disabled = isNull;
      const dateEditor = row.querySelector('[data-ms-date-editor]');
      if (dateEditor) {
        const picker = dateEditor.querySelector('[data-ms-picker-input]');
        const pickerToggle = dateEditor.querySelector('[data-ms-picker-toggle]');
        if (picker) picker.disabled = isNull || isExpression;
        if (pickerToggle) pickerToggle.disabled = isNull || isExpression;
        if (isNull || isExpression) setPickerMode(row, false);
      }
      input.classList.toggle('border-warning', isExpression && !isNull);
      input.classList.toggle('font-monospace', isExpression);
      if (!isExpression && !isNull) {
        const next = sanitize(input);
        if (next !== input.value) input.value = next;
      }
      validate(input);
    };

    form.querySelectorAll('[data-ms-smart-input]').forEach(input => {
      input.addEventListener('input', () => {
        if (!rawMode(input) && !nullMode(input)) {
          const start = input.selectionStart;
          const oldLength = input.value.length;
          const next = sanitize(input);
          if (next !== input.value) {
            input.value = next;
            if (typeof start === 'number' && typeof input.setSelectionRange === 'function') {
              const delta = input.value.length - oldLength;
              const nextPos = Math.max(0, Math.min(input.value.length, start + delta));
              input.setSelectionRange(nextPos, nextPos);
            }
          }
        }
        input.setCustomValidity('');
      });
      input.addEventListener('blur', () => validate(input));
    });

    form.querySelectorAll('[data-ms-field-row]').forEach(row => {
      const nullToggle = row.querySelector('[data-ms-null]');
      const expressionToggle = row.querySelector('[data-ms-expression]');
      if (nullToggle) nullToggle.addEventListener('change', () => syncField(row));
      if (expressionToggle) expressionToggle.addEventListener('change', () => syncField(row));
      syncField(row);
    });

    form.addEventListener('submit', event => {
      let firstInvalid = null;
      form.querySelectorAll('[data-ms-smart-input]').forEach(input => {
        if (!validate(input) && firstInvalid === null) firstInvalid = input;
      });
      if (firstInvalid) {
        event.preventDefault();
        firstInvalid.reportValidity();
        firstInvalid.focus();
      }
    });
  })();
  </script><?php
}


function page_sql(mysqli $db,?array $results,float $time): void {
  $sqlDefaultRows=ms_profile_setting_int('sqlRows',MS_SQL_ROWS_DEFAULT,1,100000);
  $tableRows=db_all($db,'SELECT TABLE_NAME,TABLE_TYPE FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() ORDER BY TABLE_NAME');
  $columnRows=db_all($db,'SELECT TABLE_NAME,COLUMN_NAME,COLUMN_TYPE,COLUMN_KEY FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() ORDER BY TABLE_NAME,ORDINAL_POSITION');
  $sqlSchema=['tables'=>[],'columns'=>[]];
  foreach($tableRows as $tableRow){$tableName=(string)$tableRow['TABLE_NAME'];$sqlSchema['tables'][]=['name'=>$tableName,'type'=>(string)$tableRow['TABLE_TYPE']];$sqlSchema['columns'][$tableName]=[];}
  foreach($columnRows as $columnRow){$tableName=(string)$columnRow['TABLE_NAME'];if(!isset($sqlSchema['columns'][$tableName]))$sqlSchema['columns'][$tableName]=[];$sqlSchema['columns'][$tableName][]=['name'=>(string)$columnRow['COLUMN_NAME'],'type'=>(string)$columnRow['COLUMN_TYPE'],'key'=>(string)$columnRow['COLUMN_KEY']];}
  $sqlSchemaJson=json_encode($sqlSchema,JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES|JSON_HEX_TAG|JSON_HEX_AMP|JSON_HEX_APOS|JSON_HEX_QUOT)?:'{"tables":[],"columns":{}}';
  title_bar('SQL command',selected_db());
  ?><div class="card mb-3"><div class="card-body"><form method="post" enctype="multipart/form-data"><input type="hidden" name="action" value="run_sql"><input type="hidden" name="row_limit" value="<?= h((string)$sqlDefaultRows) ?>" data-ms-sql-row-limit><?= csrf_field() ?><label class="form-label">SQL statements</label><textarea class="form-control sql-editor" name="sql" spellcheck="false" autocomplete="off" data-ms-sql-schema-id="ms-sql-schema"><?= h(p('sql',(string)($_SESSION['ms_last_sql']??''))) ?></textarea><script type="application/json" id="ms-sql-schema"><?= $sqlSchemaJson ?></script><div class="form-text mt-2"><i class="fa-solid fa-wand-magic-sparkles me-1"></i>Smart SQL: table suggestions after <code>SELECT</code>, <code>UPDATE</code>, <code>INSERT</code>, <code>FROM</code>, <code>JOIN</code> and related clauses; type <code>table.</code> for columns. Use ↑/↓ and Enter/Tab to accept, Esc to close, Ctrl+Space to reopen suggestions.</div><div class="row g-3 mt-1 align-items-end"><div class="col-md-7"><label class="form-label">Or import a .sql file (maximum 50 MB)</label><input class="form-control" type="file" name="sql_file" accept=".sql,text/sql,text/plain"><label class="mt-3 d-flex align-items-start gap-2"><input class="form-check-input mt-1" type="checkbox" name="show_all" value="1"<?= p('show_all') === '1' ? ' checked' : '' ?>><span><strong>Show all result rows</strong><span class="d-block form-text mt-0">The default display limit is <span data-ms-sql-limit-label><?= h(number_format($sqlDefaultRows)) ?></span> rows. Large results can use substantial browser and server memory.</span></span></label></div><div class="col-md-5 text-md-end"><div class="d-inline-flex flex-wrap justify-content-md-end gap-2"><button class="btn btn-outline-secondary" type="submit" name="sql_submit" value="explain" title="Show the optimizer execution plan without executing the statement"><i class="fa-solid fa-magnifying-glass-chart me-1"></i>Explain SQL</button><button class="btn btn-primary" type="submit" name="sql_submit" value="execute"><i class="fa-solid fa-play me-1"></i>Execute <span class="small">Ctrl+Enter</span></button></div></div></div></form></div></div><?php if(!empty($sqlExplainMode)){?><div class="alert alert-info"><i class="fa-solid fa-circle-info me-2"></i>EXPLAIN shows the optimizer plan and does not execute the submitted DML statement.</div><?php } if($results!==null)render_sql_results($results,$time);
}

function page_export(mysqli $db): void {
  $tables=db_all($db,'SELECT TABLE_NAME,TABLE_TYPE FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() ORDER BY TABLE_NAME');title_bar('Export',selected_db());
  $databaseJson=json_encode(selected_db(),JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES|JSON_HEX_TAG|JSON_HEX_AMP|JSON_HEX_APOS|JSON_HEX_QUOT)?:'"database"';
  ?><div class="card"><div class="card-body"><form method="get" id="msExportForm"><input type="hidden" name="download" value="export"><div class="row g-3"><div class="col-md-4"><label class="form-label">Format</label><select class="form-select" name="format" id="msExportFormat"><option value="sql">SQL</option><option value="csv">CSV (one table only)</option><option value="tsv">TSV (one table only)</option><option value="xls">XLS (browser-side, multiple sheets)</option></select></div><div class="col-md-8"><label class="form-label">Objects</label><select class="form-select" name="tables[]" id="msExportTables" multiple size="12"><?php foreach($tables as $t){?><option value="<?= h($t['TABLE_NAME']) ?>" selected><?= h($t['TABLE_NAME'].' · '.$t['TABLE_TYPE']) ?></option><?php }?></select><div class="form-text">Leave all selected to export the database. CSV/TSV downloads and clipboard actions require exactly one selection. XLS can export multiple selected objects as separate worksheets.</div></div><div class="col-12 d-flex flex-wrap gap-4"><label><input class="form-check-input" type="checkbox" name="structure" value="1" checked> Structure, views, routines, triggers and events</label><label><input class="form-check-input" type="checkbox" name="data" value="1" checked> Data</label><label><input class="form-check-input" type="checkbox" name="drop" value="1" checked> Add DROP statements</label></div><div class="col-12 d-flex flex-wrap align-items-center gap-2"><button class="btn btn-primary" id="msExportDownload" type="submit"><i class="fa-solid fa-download me-1"></i><span>Download export</span></button><button class="btn btn-outline-secondary" id="msCopyCsv" type="button"><i class="fa-solid fa-clipboard me-1"></i>CSV to clipboard</button><button class="btn btn-outline-secondary" id="msCopyTsv" type="button"><i class="fa-solid fa-clipboard me-1"></i>TSV to clipboard</button><span class="small text-body-secondary" id="msExportStatus" role="status" aria-live="polite"></span></div></div></form></div></div>
  <script src="https://cdn.jsdelivr.net/npm/xlsx@0.18.5/dist/xlsx.full.min.js"></script>
  <script>
  (()=>{
    'use strict';
    const form=document.getElementById('msExportForm');
    const format=document.getElementById('msExportFormat');
    const tables=document.getElementById('msExportTables');
    const download=document.getElementById('msExportDownload');
    const copyCsv=document.getElementById('msCopyCsv');
    const copyTsv=document.getElementById('msCopyTsv');
    const status=document.getElementById('msExportStatus');
    const database=<?= $databaseJson ?> || 'database';
    if(!form||!format||!tables||!download||!copyCsv||!copyTsv||!status)return;

    const selectedTables=()=>Array.from(tables.selectedOptions).map(option=>option.value);
    const setStatus=(message,type='secondary')=>{
      status.className='small text-'+type;
      status.textContent=message||'';
    };
    const setBusy=busy=>{
      [download,copyCsv,copyTsv].forEach(button=>button.disabled=busy);
      tables.disabled=busy;
      format.disabled=busy;
    };
    const exportUrl=(table,exportFormat)=>{
      const params=new URLSearchParams();
      params.set('download','export');
      params.set('format',exportFormat);
      params.append('tables[]',table);
      return '?'+params.toString();
    };
    const fetchText=async(table,exportFormat)=>{
      const response=await fetch(exportUrl(table,exportFormat),{credentials:'same-origin'});
      if(!response.ok){
        const text=await response.text();
        throw new Error(text.replace(/<[^>]*>/g,' ').replace(/\s+/g,' ').trim()||('HTTP '+response.status));
      }
      return (await response.text()).replace(/^\uFEFF/, '');
    };
    const copyText=async text=>{
      if(navigator.clipboard&&window.isSecureContext){
        await navigator.clipboard.writeText(text);
        return;
      }
      const textarea=document.createElement('textarea');
      textarea.value=text;
      textarea.setAttribute('readonly','');
      textarea.style.position='fixed';
      textarea.style.left='-9999px';
      textarea.style.top='0';
      document.body.appendChild(textarea);
      textarea.select();
      const copied=document.execCommand('copy');
      textarea.remove();
      if(!copied)throw new Error('The browser refused clipboard access.');
    };
    const safeFileName=value=>String(value||'database').replace(/[\\/:*?"<>|\x00-\x1F]+/g,'_').replace(/[. ]+$/g,'')||'database';
    const safeSheetBase=value=>String(value||'Sheet').replace(/[\\/?*\[\]:]/g,'_').slice(0,31)||'Sheet';
    const uniqueSheetName=(value,used)=>{
      const base=safeSheetBase(value);
      let name=base;
      let n=2;
      while(used.has(name.toLowerCase())){
        const suffix='_'+n++;
        name=base.slice(0,31-suffix.length)+suffix;
      }
      used.add(name.toLowerCase());
      return name;
    };
    const refresh=()=>{
      const count=selectedTables().length;
      copyCsv.disabled=count!==1;
      copyTsv.disabled=count!==1;
      const isXls=format.value==='xls';
      download.querySelector('span').textContent=isXls?'Download XLS':'Download export';
      download.querySelector('i').className=isXls?'fa-solid fa-file-excel me-1':'fa-solid fa-download me-1';
      if(isXls){
        form.querySelectorAll('input[name="structure"],input[name="drop"]').forEach(input=>input.disabled=true);
      }else{
        form.querySelectorAll('input[name="structure"],input[name="drop"]').forEach(input=>input.disabled=false);
      }
    };

    const copyFormat=async exportFormat=>{
      const selected=selectedTables();
      if(selected.length!==1){
        setStatus('Select exactly one object first.','danger');
        return;
      }
      setBusy(true);
      setStatus('Preparing '+exportFormat.toUpperCase()+'...');
      try{
        const text=await fetchText(selected[0],exportFormat);
        await copyText(text);
        setStatus(exportFormat.toUpperCase()+' copied to clipboard.','success');
      }catch(error){
        setStatus(error instanceof Error?error.message:String(error),'danger');
      }finally{
        setBusy(false);
        refresh();
      }
    };

    const downloadXls=async()=>{
      const selected=selectedTables();
      if(!selected.length){
        setStatus('Select at least one object first.','danger');
        return;
      }
      if(typeof XLSX==='undefined'){
        setStatus('The XLS library could not be loaded from the CDN.','danger');
        return;
      }
      setBusy(true);
      setStatus('Building XLS workbook...');
      try{
        const workbook=XLSX.utils.book_new();
        const used=new Set();
        for(let i=0;i<selected.length;i++){
          const table=selected[i];
          setStatus('Loading '+table+' ('+(i+1)+'/'+selected.length+')...');
          const csv=await fetchText(table,'csv');
          const parsed=XLSX.read(csv,{type:'string',raw:true});
          const sourceName=parsed.SheetNames[0];
          const worksheet=parsed.Sheets[sourceName];
          XLSX.utils.book_append_sheet(workbook,worksheet,uniqueSheetName(table,used));
        }
        const stamp=new Date().toISOString().replace(/[-:]/g,'').replace(/T/,'-').replace(/\..+$/,'');
        XLSX.writeFile(workbook,safeFileName(database)+'-'+stamp+'.xls',{bookType:'xls',compression:true});
        setStatus('XLS export created.','success');
      }catch(error){
        setStatus(error instanceof Error?error.message:String(error),'danger');
      }finally{
        setBusy(false);
        refresh();
      }
    };

    copyCsv.addEventListener('click',()=>copyFormat('csv'));
    copyTsv.addEventListener('click',()=>copyFormat('tsv'));
    tables.addEventListener('change',refresh);
    format.addEventListener('change',refresh);
    form.addEventListener('submit',event=>{
      const selected=selectedTables();
      if(format.value==='xls'){
        event.preventDefault();
        downloadXls();
        return;
      }
      if((format.value==='csv'||format.value==='tsv')&&selected.length!==1){
        event.preventDefault();
        setStatus(format.value.toUpperCase()+' export requires exactly one selected object.','danger');
      }
    });
    refresh();
  })();
  </script><?php
}

function page_schema(mysqli $db): void {
  $tables=db_all($db,"SELECT TABLE_NAME FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_TYPE='BASE TABLE' ORDER BY TABLE_NAME");$foreign=db_all($db,"SELECT TABLE_NAME,COLUMN_NAME,REFERENCED_TABLE_NAME,REFERENCED_COLUMN_NAME,CONSTRAINT_NAME FROM information_schema.KEY_COLUMN_USAGE WHERE TABLE_SCHEMA=DATABASE() AND REFERENCED_TABLE_NAME IS NOT NULL ORDER BY TABLE_NAME,CONSTRAINT_NAME,ORDINAL_POSITION");$refs=[];foreach($foreign as $f)$refs[$f['TABLE_NAME']][$f['COLUMN_NAME']]=$f;
  title_bar('Database schema',selected_db(),'<button class="btn btn-primary" onclick="window.print()"><i class="fa-solid fa-print me-1"></i>Print</button>');
  ?>
  <div class="schema-width-picker d-none d-md-flex flex-wrap align-items-center gap-2 mb-3 no-print">
    <span class="small text-body-secondary me-1">Table width:</span>
    <div class="btn-group btn-group-sm" role="group" aria-label="Schema table width">
      <?php foreach([2,3,4,6,12] as $width){ ?><button type="button" class="btn btn-outline-secondary" data-ms-schema-col="<?= $width ?>">col-md-<?= $width ?></button><?php } ?>
    </div>
  </div>
  <div class="schema-canvas p-2">
    <div class="row g-2 schema-grid" data-ms-schema-grid>
      <?php foreach($tables as $t){$name=(string)$t['TABLE_NAME'];$cols=table_columns($db,$name);?>
        <div class="schema-col col-12 col-md-3" data-ms-schema-column>
          <section class="schema-table card shadow-sm h-100">
            <div class="card-header fw-bold"><i class="fa-solid fa-table me-1"></i><?= h($name) ?></div>
            <ul class="list-group list-group-flush small"><?php foreach($cols as $c){$ref=$refs[$name][$c['COLUMN_NAME']]??null;?><li class="list-group-item d-flex justify-content-between gap-2 flex-wrap"><span><?= h($c['COLUMN_NAME']) ?><?php if($c['COLUMN_KEY']==='PRI'){?> <i class="fa-solid fa-key text-warning"></i><?php }?></span><span class="text-body-secondary"><?= h($c['COLUMN_TYPE']) ?></span><?php if($ref){?><div class="schema-line w-100"><i class="fa-solid fa-arrow-right"></i> <?= h($ref['REFERENCED_TABLE_NAME'].'.'.$ref['REFERENCED_COLUMN_NAME']) ?></div><?php }?></li><?php }?></ul>
          </section>
        </div>
      <?php } ?>
    </div>
  </div>
  <script>
  (()=>{
    'use strict';
    const allowed=[2,3,4,6,12];
    const initialProfileWidth=<?= h((string)ms_profile_setting_int('schemaColumnWidth',3,2,12)) ?>;
    const columns=Array.from(document.querySelectorAll('[data-ms-schema-column]'));
    const buttons=Array.from(document.querySelectorAll('[data-ms-schema-col]'));
    if(!columns.length||!buttons.length)return;
    const apply=value=>{
      const width=allowed.includes(Number(value))?Number(value):3;
      columns.forEach(column=>{
        allowed.forEach(size=>column.classList.remove('col-md-'+size));
        column.classList.add('col-md-'+width);
      });
      buttons.forEach(button=>{
        const active=Number(button.dataset.msSchemaCol)===width;
        button.classList.toggle('btn-secondary',active);
        button.classList.toggle('btn-outline-secondary',!active);
        button.setAttribute('aria-pressed',active?'true':'false');
      });
    };
    apply(allowed.includes(Number(initialProfileWidth))?Number(initialProfileWidth):3);
    buttons.forEach(button=>button.addEventListener('click',async()=>{
      const width=Number(button.dataset.msSchemaCol);apply(width);
      try{await window.msConfigPost('schema_width',{width:String(width)});}catch(error){alert(error.message||String(error));}
    }));
  })();
  </script><?php
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

function render_column_display_settings(): void {
  $database = selected_db();
  ?><section class="card mt-4 mb-3"><div class="card-header d-flex flex-wrap justify-content-between align-items-center gap-2"><h2 class="h5 mb-0"><i class="fa-solid fa-table-columns me-2"></i>Column display rules</h2><?php if($database!==''){?><span class="badge text-bg-secondary"><?= h($database) ?></span><?php }?></div><div class="card-body"><?php
  if ($database === '') {
    ?><div class="alert alert-info mb-0">Choose a database first to manage hidden columns, custom field names, formatting, image displays and soft foreign keys.</div><?php
  } else {
    $databaseConfig = ms_column_view_database_config($database);
    $tables = isset($databaseConfig['tables']) && is_array($databaseConfig['tables']) ? $databaseConfig['tables'] : [];
    $hidden = []; $labels = []; $images = []; $softFks = [];
    foreach ($tables as $table => $tableConfig) {
      if (!is_array($tableConfig)) continue;
      foreach ((array)($tableConfig['hidden'] ?? []) as $column => $enabled) if ($enabled) $hidden[] = [(string)$table, (string)$column];
      foreach ((array)($tableConfig['labels'] ?? []) as $column => $label) if ((string)$label !== '') $labels[] = [(string)$table, (string)$column, (string)$label];
      foreach ((array)($tableConfig['images'] ?? []) as $column => $rule) if (is_array($rule)) $images[] = [(string)$table, (string)$column, $rule];
      foreach ((array)($tableConfig['soft_fk'] ?? []) as $column => $rule) if (is_array($rule)) $softFks[] = [(string)$table, (string)$column, $rule];
    }
    ?><p class="text-body-secondary">These rules are stored inside the active profile in <code><?= h(ms_profile_config_file()) ?></code> for this connection/database. They affect table browsing, including filtered, single-row and linked-table result views; they do not alter the database schema or exported data.</p>
    <div class="card mb-3"><div class="card-header d-flex flex-wrap justify-content-between align-items-center gap-2"><strong><i class="fa-solid fa-eye-slash me-2"></i>Hidden columns</strong><?php if($hidden){?><form method="post" class="m-0"><input type="hidden" name="action" value="column_view_show_all"><?= csrf_field() ?><button class="btn btn-secondary btn-sm"><i class="fa-solid fa-eye me-1"></i>Show all</button></form><?php }?></div><div class="card-body p-0"><?php if(!$hidden){?><div class="p-3 text-body-secondary">No hidden columns.</div><?php }else{?><div class="table-responsive"><table class="table table-sm align-middle mb-0"><thead><tr><th>Table</th><th>Column</th><th></th></tr></thead><tbody><?php foreach($hidden as [$table,$column]){?><tr><td><?= h($table) ?></td><td class="code"><?= h($column) ?></td><td class="text-end"><form method="post" class="d-inline"><input type="hidden" name="action" value="column_view_show"><input type="hidden" name="config_table" value="<?= h($table) ?>"><input type="hidden" name="config_column" value="<?= h($column) ?>"><?= csrf_field() ?><button class="btn btn-secondary btn-sm"><i class="fa-solid fa-eye me-1"></i>Show</button></form></td></tr><?php }?></tbody></table></div><?php }?></div></div>
    <div class="card mb-3"><div class="card-header"><strong><i class="fa-solid fa-tag me-2"></i>Custom field names</strong></div><div class="card-body p-0"><?php if(!$labels){?><div class="p-3 text-body-secondary">No custom field names.</div><?php }else{?><div class="table-responsive"><table class="table table-sm align-middle mb-0"><thead><tr><th>Table</th><th>Database field</th><th>Displayed name</th></tr></thead><tbody><?php foreach($labels as [$table,$column,$label]){?><tr><td><?= h($table) ?></td><td class="code"><?= h($column) ?></td><td><?= h($label) ?></td></tr><?php }?></tbody></table></div><?php }?></div></div>
    <div class="card mb-3"><div class="card-header"><strong><i class="fa-solid fa-image me-2"></i>Image columns</strong></div><div class="card-body p-0"><?php if(!$images){?><div class="p-3 text-body-secondary">No image display rules.</div><?php }else{?><div class="table-responsive"><table class="table table-sm align-middle mb-0"><thead><tr><th>Table</th><th>Column</th><th>URL prefix</th><th>Width</th><th></th></tr></thead><tbody><?php foreach($images as [$table,$column,$rule]){?><tr><td><?= h($table) ?></td><td class="code"><?= h($column) ?></td><td class="code text-break"><?= h((string)($rule['base_url']??'')) ?></td><td><?= h((string)($rule['width']??96)) ?> px</td><td class="text-end"><form method="post" class="d-inline"><input type="hidden" name="action" value="column_view_image_remove"><input type="hidden" name="config_table" value="<?= h($table) ?>"><input type="hidden" name="config_column" value="<?= h($column) ?>"><?= csrf_field() ?><button class="btn btn-danger btn-sm" data-confirm="Remove image display for this column?"><i class="fa-solid fa-xmark me-1"></i>Remove</button></form></td></tr><?php }?></tbody></table></div><?php }?></div></div>
    <div class="card"><div class="card-header"><strong><i class="fa-solid fa-link me-2"></i>Soft foreign keys</strong></div><div class="card-body p-0"><?php if(!$softFks){?><div class="p-3 text-body-secondary">No soft foreign keys.</div><?php }else{?><div class="table-responsive"><table class="table table-sm align-middle mb-0"><thead><tr><th>Source</th><th>Target table</th><th>ID column</th><th>Display column</th><th></th></tr></thead><tbody><?php foreach($softFks as [$table,$column,$rule]){?><tr><td><span class="code"><?= h($table.'.'.$column) ?></span></td><td><?= h((string)($rule['table']??'')) ?></td><td class="code"><?= h((string)($rule['id_column']??'')) ?></td><td class="code"><?= h((string)($rule['value_column']??'')) ?></td><td class="text-end"><form method="post" class="d-inline"><input type="hidden" name="action" value="column_view_soft_fk_remove"><input type="hidden" name="config_table" value="<?= h($table) ?>"><input type="hidden" name="config_column" value="<?= h($column) ?>"><?= csrf_field() ?><button class="btn btn-danger btn-sm" data-confirm="Remove this soft foreign key?"><i class="fa-solid fa-xmark me-1"></i>Remove</button></form></td></tr><?php }?></tbody></table></div><?php }?></div></div><?php
  }
  ?></div></section><?php
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
  $settingsSidebarObjects = [];
  $settingsDbName = selected_db();
  if ($settingsDbName !== '') {
    try {
      $settingsDb = connect_db();
      $settingsTables = db_all($settingsDb, "SELECT TABLE_NAME, TABLE_TYPE FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() ORDER BY TABLE_NAME");
      foreach ($settingsTables as $settingsTable) {
        $settingsName = (string)$settingsTable['TABLE_NAME'];
        $settingsSidebarObjects[] = [
          'name' => $settingsName,
          'type' => (string)$settingsTable['TABLE_TYPE'],
          'key' => $settingsName
        ];
      }
    } catch (Throwable $ignored) {}
  }
  $activeProfile = ms_active_profile_name();
  $profileNames = ms_profile_names();
  title_bar('Settings', 'Profile: ' . $activeProfile . ' · all preferences and database display customizations are profile-specific.');
  $updateCache = ms_update_cache_read();
  $updateCheckedAt = (int)($updateCache['checked_at'] ?? 0);
  $updateRemoteVersion = trim((string)($updateCache['remote_version'] ?? ''));
  $updateStatus = trim((string)($updateCache['status'] ?? 'never'));
  $updateMessage = trim((string)($updateCache['message'] ?? ''));
  $updateStatusLabels = [
    'never' => 'Not checked yet',
    'current' => 'Up to date',
    'updated' => 'Updated',
    'install_failed' => 'Update available - installation failed',
    'check_failed' => 'Check failed'
  ];
  $updateStatusLabel = $updateStatusLabels[$updateStatus] ?? ucfirst(str_replace('_', ' ', $updateStatus));
  ?><section class="card mb-3"><div class="card-header d-flex flex-wrap justify-content-between align-items-center gap-2"><h2 class="h5 mb-0"><i class="fa-solid fa-cloud-arrow-down me-2"></i>Software update</h2><a class="btn btn-primary btn-sm" href="<?= h(url(['ms_check_update' => '1'])) ?>"><i class="fa-solid fa-rotate me-1"></i>Check for new version</a></div><div class="card-body">
    <div class="row g-3">
      <div class="col-md-3"><div class="small text-body-secondary">Installed version</div><div class="fw-semibold">v<?= h(MS_VERSION) ?></div></div>
      <div class="col-md-3"><div class="small text-body-secondary">Last checked</div><div class="fw-semibold"><?= $updateCheckedAt > 0 ? h(date('Y-m-d H:i:s', $updateCheckedAt)) : 'Never' ?></div></div>
      <div class="col-md-3"><div class="small text-body-secondary">GitHub version</div><div class="fw-semibold"><?= $updateRemoteVersion !== '' ? 'v' . h($updateRemoteVersion) : 'Unknown' ?></div></div>
      <div class="col-md-3"><div class="small text-body-secondary">Status</div><div class="fw-semibold"><?= h($updateStatusLabel) ?></div></div>
      <?php if ($updateMessage !== '') { ?><div class="col-12"><div class="alert alert-warning mb-0"><?= h($updateMessage) ?></div></div><?php } ?>
      <div class="col-12"><div class="small text-body-secondary">The automatic check runs at most once every <?= h((string)(MS_UPDATE_CHECK_SECONDS / 3600)) ?> hours. The shared update state is stored in <code><?= h(ms_update_runtime_file('update.json')) ?></code>. Clicking the version number or this button bypasses the cache and checks GitHub immediately.</div></div>
    </div>
  </div></section>
  <section class="card mb-3"><div class="card-header"><h2 class="h5 mb-0"><i class="fa-solid fa-user-gear me-2"></i>Profiles</h2></div><div class="card-body">
    <div class="row g-3 align-items-end"><div class="col-lg-4"><div class="small text-body-secondary">Active profile</div><div class="fs-5 fw-semibold"><?= h($activeProfile) ?></div><div class="form-text">Configuration file: <code><?= h(ms_profile_config_file()) ?></code></div></div>
    <div class="col-lg-4"><form method="post" class="row g-2"><input type="hidden" name="action" value="create_profile"><?= csrf_field() ?><div class="col"><label class="form-label">New profile</label><input class="form-control" name="profile_name" maxlength="80" required></div><div class="col-auto align-self-end"><button class="btn btn-primary"><i class="fa-solid fa-plus me-1"></i>Create</button></div></form></div>
    <?php if($activeProfile!=='Default'){ ?><div class="col-lg-4"><div class="d-flex flex-wrap gap-2"><form method="post" class="d-flex gap-2 flex-grow-1"><input type="hidden" name="action" value="rename_profile"><?= csrf_field() ?><input class="form-control" name="profile_name" value="<?= h($activeProfile) ?>" maxlength="80" required><button class="btn btn-secondary text-nowrap"><i class="fa-solid fa-pen me-1"></i>Rename</button></form><form method="post"><input type="hidden" name="action" value="delete_profile"><?= csrf_field() ?><button class="btn btn-danger" data-confirm="Delete profile <?= h($activeProfile) ?> and all of its settings?"><i class="fa-solid fa-trash"></i></button></form></div></div><?php } ?>
    </div><div class="form-text mt-3">Default always exists. New profiles start with clean defaults. No legacy configuration is imported.</div>
  </div></section>
  <form id="ms-settings-form" method="post"><input type="hidden" name="action" value="save_profile_settings"><?= csrf_field() ?>
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
      <div class="col-12"><label class="form-label d-block">Table pagination position</label><div class="btn-group flex-wrap" role="group" aria-label="Table pagination position"><input class="btn-check" type="radio" name="paginationPosition" id="pagination-top" value="top"><label class="btn btn-outline-secondary" for="pagination-top"><i class="fa-solid fa-arrow-up me-1"></i>Top</label><input class="btn-check" type="radio" name="paginationPosition" id="pagination-bottom" value="bottom"><label class="btn btn-outline-secondary" for="pagination-bottom"><i class="fa-solid fa-arrow-down me-1"></i>Bottom</label><input class="btn-check" type="radio" name="paginationPosition" id="pagination-both" value="both"><label class="btn btn-outline-secondary" for="pagination-both"><i class="fa-solid fa-arrows-up-down me-1"></i>Both</label></div><div class="form-text">Choose where page navigation is shown while browsing table contents.</div></div>
      <div class="col-12"><div class="border rounded p-3"><div class="form-check form-switch"><input class="form-check-input" type="checkbox" role="switch" name="truncateCells" value="1" id="settings-truncate-cells"><label class="form-check-label fw-semibold" for="settings-truncate-cells">Thin, single-line table rows</label></div><div class="form-text ms-4">Keep every displayed cell on one line and replace overflowing text with an ellipsis. The complete value is not changed in the database.</div></div></div>
      <div class="col-12"><div class="alert alert-info mb-0"><i class="fa-solid fa-table-columns me-2"></i>Column order is saved automatically per profile/table. Column widths are saved only when you press <strong>Save Widths</strong> on the Select page. Left-sidebar visibility, display rules and saved searches are also profile-specific. Restore defaults resets the complete active profile.</div></div>
    </div></div></section>

    <section class="card mb-3"><div class="card-header d-flex flex-wrap justify-content-between align-items-center gap-2"><h2 class="h5 mb-0"><i class="fa-solid fa-bars me-2"></i>Left menu</h2><div><button class="btn btn-secondary btn-sm" type="button" id="ms-menu-show-all">Show all</button> <button class="btn btn-secondary btn-sm" type="button" id="ms-menu-hide-all">Hide all</button></div></div><div class="card-body"><p class="text-body-secondary">Choose which database tools appear in the left navigation. Settings and Log out always remain visible.</p><div class="row g-2"><?php foreach ($menuItems as $key => [$icon, $label]) { ?>
      <div class="col-md-6 col-xl-4"><label class="border rounded p-3 d-flex align-items-center gap-3 h-100"><input class="form-check-input mt-0" type="checkbox" name="menu[<?= h($key) ?>]" value="1"><i class="fa-solid <?= h($icon) ?> fa-fw text-primary"></i><span><?= h($label) ?></span></label></div>
    <?php } ?></div></div></section>

    <section class="card mb-3" id="ms-hidden-sidebar-section"><div class="card-header d-flex flex-wrap justify-content-between align-items-center gap-2"><h2 class="h5 mb-0"><i class="fa-solid fa-eye-slash me-2"></i>Hidden sidebar tables</h2><button class="btn btn-secondary btn-sm" type="button" id="ms-sidebar-show-all-hidden"><i class="fa-solid fa-eye me-1"></i>Show all</button></div><div class="card-body">
      <p class="text-body-secondary">Tables and views hidden from the normal left sidebar are listed here so they can be re-enabled individually. Raw DB view always shows every object regardless of this setting.</p>
      <?php if ($settingsDbName === '') { ?><div class="alert alert-secondary mb-0">Choose a database first to manage hidden sidebar tables.</div><?php } else { ?>
        <div id="ms-hidden-sidebar-empty" class="alert alert-success mb-0"><i class="fa-solid fa-circle-check me-2"></i>No tables or views are hidden in <strong><?= h($settingsDbName) ?></strong>.</div>
        <div class="table-responsive" id="ms-hidden-sidebar-table-wrap"><table class="table table-sm align-middle mb-0"><thead><tr><th>Name</th><th>Type</th><th class="text-end">Action</th></tr></thead><tbody><?php foreach ($settingsSidebarObjects as $settingsObject) { ?>
          <tr data-ms-hidden-sidebar-row data-ms-hidden-sidebar-key="<?= h($settingsObject['key']) ?>" hidden><td><i class="fa-solid <?= $settingsObject['type']==='VIEW'?'fa-eye':'fa-table' ?> fa-fw me-2 text-body-secondary"></i><?= h($settingsObject['name']) ?></td><td><?= h($settingsObject['type']) ?></td><td class="text-end"><button class="btn btn-outline-primary btn-sm" type="button" data-ms-sidebar-restore="<?= h($settingsObject['key']) ?>"><i class="fa-solid fa-eye me-1"></i>Show</button></td></tr>
        <?php } ?></tbody></table></div>
      <?php } ?>
    </div></section>

    <div class="d-flex flex-wrap gap-2"><button class="btn btn-primary" type="submit"><i class="fa-solid fa-floppy-disk me-1"></i>Save settings</button><button class="btn btn-secondary" type="button" id="ms-settings-reset"><i class="fa-solid fa-rotate-left me-1"></i>Restore defaults</button></div>
  </form><?php
  render_column_display_settings();
}

if (empty($_SESSION['ms_login'])) {
  page_login($error);
  exit;
}

try {
  $db = connect_db(false);
  $page = g('page', selected_db() !== '' ? 'database' : 'databases');
  $allowedPages = ms_allowed_pages();
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
