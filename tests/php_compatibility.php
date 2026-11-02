<?php
/** Database-independent compatibility regressions; run on every supported PHP version. */
declare(strict_types=1);
require __DIR__ . '/deprecations.php';
ini_set('session.save_path', sys_get_temp_dir());
define('MS_LIBRARY_ONLY', true);
require dirname(__DIR__) . '/index.php';

$checks = 0;
$failures = 0;
function compat_check(string $name, callable $test): void {
  global $checks, $failures;
  $checks++;
  try { $test(); echo "PASS $name\n"; }
  catch (Throwable $e) { $failures++; echo "FAIL $name: " . $e->getMessage() . "\n"; }
}
function compat_same($actual, $expected): void {
  if ($actual !== $expected) throw new RuntimeException('Expected ' . var_export($expected, true) . ', got ' . var_export($actual, true));
}

compat_check('Startup keeps cookie-only sessions enabled', static function (): void {
  compat_same(ini_get('session.use_only_cookies'), '1');
  compat_same(session_status(), PHP_SESSION_ACTIVE);
});

foreach (['comma'=>',', 'semicolon'=>';', 'tab'=>"\t", 'pipe'=>'|'] as $choice => $delimiter) {
  compat_check('CSV import and auto-detection: ' . $choice, static function () use ($choice, $delimiter): void {
    $file = tempnam(sys_get_temp_dir(), 'ms-csv-test-');
    try {
      $csv = "\xEF\xBB\xBFid" . $delimiter . 'name' . $delimiter . 'note' . "\r\n"
        . '1' . $delimiter . '"O\'Brien ภาษาไทย"' . $delimiter . '"comma, semicolon; tab' . "\t" . ' pipe| and ""quotes"""' . "\r\n"
        . '2' . $delimiter . 'second' . $delimiter . '"two' . "\n" . 'lines and C:\\folder\\file"' . "\r\n";
      file_put_contents($file, $csv);
      $expected = [
        ['id', 'name', 'note'],
        [['1', "O'Brien ภาษาไทย", "comma, semicolon; tab\t pipe| and \"quotes\""], ['2', 'second', "two\nlines and C:\\folder\\file"]],
        $delimiter
      ];
      compat_same(ms_import_parse_csv_file($file, $choice), $expected);
      compat_same(ms_import_parse_csv_file($file, 'auto'), $expected);
    } finally { unlink($file); }
  });
  compat_check('CSV export preserves backslashes and quotes: ' . $choice, static function () use ($delimiter): void {
    $row = ['trailing\\', 'slash\\"quote', "line\nbreak", '"double"', "ภาษาไทย 🐘", '', "a\0b"];
    $stream = fopen('php://temp', 'w+b');
    try {
      ms_export_csv_row($stream, $row, $delimiter);
      rewind($stream);
      compat_same(fgetcsv($stream, 0, $delimiter, '"', ''), $row);
      compat_same(fgetcsv($stream, 0, $delimiter, '"', ''), false);
    } finally { fclose($stream); }
  });
}

compat_check('Legacy backslash-escaped CSV imports keep their existing meaning', static function (): void {
  $file = tempnam(sys_get_temp_dir(), 'ms-csv-test-');
  try {
    file_put_contents($file, "id,text\n" . '1,"a\"b,c"' . "\n");
    [$headers, $rows] = ms_import_parse_csv_file($file, 'auto');
    compat_same($headers, ['id', 'text']);
    compat_same($rows, [['1', 'a\"b,c']]);
  } finally { unlink($file); }
});

echo "$checks compatibility checks, $failures failures on PHP " . PHP_VERSION . "\n";
exit($failures ? 1 : 0);
