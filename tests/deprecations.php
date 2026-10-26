<?php
/** Fail regression runs even when application code catches or suppresses a deprecation. */
declare(strict_types=1);
error_reporting(E_ALL);
$msTestDeprecations = [];
set_error_handler(static function (int $severity, string $message, string $file, int $line) use (&$msTestDeprecations): bool {
  if (($severity & (E_DEPRECATED | E_USER_DEPRECATED)) !== 0) {
    $msTestDeprecations[] = $message . ' at ' . $file . ':' . $line;
    return true;
  }
  return false;
});
register_shutdown_function(static function () use (&$msTestDeprecations): void {
  if ($msTestDeprecations) {
    fwrite(STDERR, "PHP deprecations detected:\n" . implode("\n", array_unique($msTestDeprecations)) . "\n");
    exit(1);
  }
});
