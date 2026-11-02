<?php
/** SQLite tools use disposable files only; run on every supported PHP version. */
declare(strict_types=1);
require __DIR__ . '/deprecations.php';
ini_set('session.save_path', sys_get_temp_dir());
define('MS_LIBRARY_ONLY', true);
require dirname(__DIR__) . '/index.php';

$checks = 0; $failures = 0;
function check(string $name, callable $fn): void {
  global $checks, $failures;
  $checks++;
  try { $fn(); echo "PASS $name\n"; }
  catch (Throwable $e) { $failures++; echo "FAIL $name: " . $e->getMessage() . "\n"; }
}
function same($actual, $expected): void {
  if ($actual !== $expected) throw new RuntimeException('Expected ' . var_export($expected,true) . ', got ' . var_export($actual,true));
}
function rejects(callable $fn): void {
  try { $fn(); } catch (Throwable $e) { return; }
  throw new RuntimeException('Expected operation to fail.');
}
function output_of(callable $fn): string {
  $out = fopen('php://temp','w+b');
  try { $fn($out); rewind($out); return stream_get_contents($out); }
  finally { fclose($out); }
}
function import_rows(MSDatabase $db, string $table, array $headers, array $rows, string $mode = 'insert', string $key = '', bool $emptyNull = false): array {
  $path = tempnam(sys_get_temp_dir(),'ms-sqlite-import-test-');
  $before = $_POST;
  try {
    $objects = array_map(static function (array $row) use ($headers): array { return array_combine($headers,$row); },$rows);
    file_put_contents($path,json_encode($objects));
    $token = ms_import_create_preview($path,'fixture.json','auto');
    $_POST = ['import_table'=>$table,'mapping'=>$headers,'import_mode'=>$mode,'import_key'=>$key,'empty_as_null'=>$emptyNull?'1':'0'];
    return ms_import_execute_rows($db,$token);
  } finally { $_POST = $before; unlink($path); }
}

$root = sys_get_temp_dir() . '/ms-sqlite-tools-' . bin2hex(random_bytes(8));
mkdir($root,0700);
putenv('MS_SQLITE_ROOT=' . $root);
$hash = password_hash('test-only',PASSWORD_DEFAULT);
putenv('MS_SQLITE_PASSWORD_HASH=' . $hash);
$source = $root . '/source.sqlite'; $target = $root . '/target.sqlite';
foreach ([$source,$target] as $path) {
  $native = new PDO('sqlite:' . $path);
  $native->exec('CREATE TABLE bootstrap(id INTEGER)');
  $native = null;
}
$_SESSION['ms_login'] = ['engine'=>'sqlite','path'=>$source,'sqlite_auth'=>hash('sha256',$hash),'user'=>'SQLite administrator'];
$_SESSION['ms_db'] = 'main';
$db = new MSSQLiteDatabase($source); $restored = new MSSQLiteDatabase($target);
$GLOBALS['db'] = $db;
try {
  $db->run('CREATE TABLE items(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE, value, amount NUMERIC DEFAULT 7, doubled NUMERIC GENERATED ALWAYS AS (amount * 2) STORED)');
  $db->run("INSERT INTO items(id,name,value,amount) VALUES (1,'first',NULL,1.25),(2,'empty','',-0.00000000000012345678901234567),(3,'blob',X'00FF27',9e999),(4,'text',CAST(X'610062' AS TEXT),-9e999),(100,'deleted',NULL,7)");
  $db->run('DELETE FROM items WHERE id=100');
  $db->run('CREATE TABLE big(id INTEGER PRIMARY KEY, value)');
  $db->run("INSERT INTO big VALUES (9223372036854775807,9223372036854775807),(-9223372036854775808,-9223372036854775808)");
  $db->run('CREATE TABLE no_key(value TEXT)');
  $db->run("INSERT INTO no_key(rowid,value) VALUES (11,'same'),(25,'same')");
  $db->run('CREATE TABLE composite(a TEXT,b INTEGER,value TEXT,PRIMARY KEY(a,b)) WITHOUT ROWID');
  $db->run("INSERT INTO composite VALUES ('key',1,'value')");
  $db->run('CREATE TABLE child(id INTEGER PRIMARY KEY,parent INTEGER REFERENCES items(id) ON DELETE CASCADE)');
  $db->run('INSERT INTO child VALUES (1,1)');
  $db->run('CREATE TABLE audit(id INTEGER)');
  $db->run('CREATE INDEX ix_items_amount ON items(amount) WHERE amount > 0');
  $db->run('CREATE VIEW item_names AS SELECT id,name FROM items');
  $db->run('CREATE TRIGGER insert_audit AFTER INSERT ON items BEGIN INSERT INTO audit VALUES (new.id); END');
  $allTables = array_column(ms_table_list($db),'TABLE_NAME');
  $dump = output_of(static function ($out) use ($db,$allTables): void { dump_database($db,$allTables,true,true,true,$out); });
  check('SQL dump is SQLite-only and excludes generated column INSERTs', static function () use ($dump): void {
    same(strpos($dump,'FOREIGN_KEY_CHECKS'),false);
    same(strpos($dump,'SET NAMES'),false);
    same(strpos($dump,'INSERT INTO ' . qi('items') . ' (' . implode(', ',array_map('qi',['id','name','value','amount'])) . ')')!==false,true);
  });
  check('SQL dump restores atomically into a second file', static function () use ($restored,$dump): void { same(ms_sqlite_restore($restored,$dump)>0,true); });
  check('SQL round-trip retains storage classes, NUL, BLOB and REAL precision', static function () use ($db,$restored): void {
    $sql = "SELECT CAST(id AS TEXT) AS id,name,typeof(value) AS storage,hex(value) AS bytes,printf('%!.26g',amount) AS amount,printf('%!.26g',doubled) AS doubled FROM items ORDER BY id";
    same(db_all($restored,$sql),db_all($db,$sql));
    same(db_all($restored,'SELECT CAST(id AS TEXT) AS id,CAST(value AS TEXT) AS value,typeof(value) AS storage FROM big ORDER BY id'),db_all($db,'SELECT CAST(id AS TEXT) AS id,CAST(value AS TEXT) AS value,typeof(value) AS storage FROM big ORDER BY id'));
  });
  check('SQL dump preserves rowid gaps and WITHOUT ROWID keys', static function () use ($db,$restored): void {
    same(db_all($restored,'SELECT CAST(rowid AS TEXT) AS rowid,value FROM no_key'),db_all($db,'SELECT CAST(rowid AS TEXT) AS rowid,value FROM no_key'));
    same(primary_columns($restored,'composite'),['a','b']);
  });
  check('Indexes, views, triggers and AUTOINCREMENT high-water mark restored', static function () use ($restored): void {
    same((string)db_one($restored,'SELECT count(*) AS n FROM audit')['n'],'0');
    same((string)db_one($restored,'SELECT count(*) AS n FROM item_names')['n'],'4');
    same(db_one($restored,"SELECT name FROM sqlite_master WHERE name='ix_items_amount'")['name'],'ix_items_amount');
    $restored->run("INSERT INTO items(name) VALUES ('next')");
    same((string)db_one($restored,"SELECT id FROM items WHERE name='next'")['id'],'101');
    same((string)db_one($restored,'SELECT id FROM audit')['id'],'101');
  });
  check('Restore DROP does not cascade into unselected child rows', static function () use ($db): void {
    $sql = output_of(static function ($out) use ($db): void { dump_database($db,['items'],true,true,true,$out); });
    ms_sqlite_restore($db,$sql);
    same((string)db_one($db,'SELECT parent FROM child')['parent'],'1');
  });
  check('Invalid restore rolls back schema and data, keeps FK enforcement', static function () use ($db): void {
    rejects(static function () use ($db): void { ms_sqlite_restore($db,'CREATE TABLE transient(value); DELETE FROM child; INSERT INTO missing VALUES (1)'); });
    same(table_exists($db,'transient'),false);
    same((string)db_one($db,'SELECT count(*) AS n FROM child')['n'],'1');
    same((string)db_one($db,'PRAGMA foreign_keys')['foreign_keys'],'1');
  });
  check('Restore rejects foreign-key violations and unsafe SQL before writing', static function () use ($db): void {
    rejects(static function () use ($db): void { ms_sqlite_restore($db,'DELETE FROM items WHERE id=1'); });
    foreach (["ATTACH ':memory:' AS bad",'PRAGMA foreign_keys=OFF','BEGIN','VACUUM',"SELECT writefile('/tmp/no','x')"] as $unsafe) rejects(static function () use ($db,$unsafe): void { ms_sqlite_restore($db,'DELETE FROM child; ' . $unsafe); });
    same((string)db_one($db,'SELECT count(*) AS n FROM child')['n'],'1');
    same((string)db_one($db,'SELECT count(*) AS n FROM items')['n'],'4');
  });
  check('SQLite result export handles empty metadata and duplicate aliases', static function () use ($db): void {
    $csv = output_of(static function ($out) use ($db): void { ms_sqlite_export_result($db,'SELECT id AS x,name AS x FROM items WHERE 0','csv',$out,null,false); });
    same(trim($csv),'x,x:1');
    same($db->sqlite()->inTransaction(),false);
    same(db_all($db,"SELECT name FROM sqlite_temp_master WHERE name LIKE '__ms_export_%'"),[]);
  });
  check('SQL query export preserves full 64-bit integers independently of PHP', static function () use ($db,$restored): void {
    $sql = output_of(static function ($out) use ($db): void { ms_sqlite_export_result($db,'SELECT * FROM big ORDER BY id','sql',$out); });
    ms_sqlite_restore($restored,$sql);
    same(db_all($restored,'SELECT CAST(id AS TEXT) AS id,CAST(value AS TEXT) AS value FROM query_result ORDER BY id'),db_all($db,'SELECT CAST(id AS TEXT) AS id,CAST(value AS TEXT) AS value FROM big ORDER BY id'));
  });
  check('SQLite export refuses mutating results and stacked statements', static function () use ($db): void {
    foreach (['DELETE FROM items RETURNING *','SELECT 1; DELETE FROM items','WITH x AS (SELECT 1) DELETE FROM items RETURNING *'] as $sql) rejects(static function () use ($db,$sql): void { output_of(static function ($out) use ($db,$sql): void { ms_sqlite_export_result($db,$sql,'csv',$out); }); });
  });
  check('Quoted/numeric identifiers survive dump and restore', static function () use ($db,$restored): void {
    foreach (['123','odd " table'] as $table) {
      $db->run('CREATE TABLE ' . qi($table) . ' (' . qi('0') . ' TEXT, ' . qi('a"b') . ' TEXT)');
      $db->run('INSERT INTO ' . qi($table) . ' VALUES (?,?)', ['numbered','quoted']);
      $sql = output_of(static function ($out) use ($db,$table): void { dump_database($db,[$table],true,true,true,$out); });
      ms_sqlite_restore($restored,$sql);
      same(db_one($restored,'SELECT * FROM ' . qi($table)),db_one($db,'SELECT * FROM ' . qi($table)));
    }
  });
  check('Volatile query expressions are evaluated once per exported row', static function () use ($db): void {
    $calls = 0;
    $callback = static function () use (&$calls): string { $calls++; return 'value-' . $calls; };
    if (method_exists($db->sqlite(),'createFunction')) $db->sqlite()->createFunction('ms_test_volatile',$callback,0);
    else $db->sqlite()->sqliteCreateFunction('ms_test_volatile',$callback,0);
    output_of(static function ($out) use ($db): void { ms_sqlite_export_result($db,'SELECT ms_test_volatile() AS value','sql',$out); });
    same($calls,1);
  });
  check('Export failures release the cursor, temporary view and read transaction', static function () use ($db): void {
    rejects(static function () use ($db): void { output_of(static function ($out) use ($db): void { ms_sqlite_export_result($db,'SELECT * FROM items','csv',$out,['missing_column']); }); });
    same($db->sqlite()->inTransaction(),false);
    same(db_all($db,"SELECT name FROM sqlite_temp_master WHERE name LIKE '__ms_export_%'"),[]);
  });
  check('CSV and TSV preserve quoted backslashes, delimiters, newlines and UTF-8', static function () use ($db,$root): void {
    $value = "\\\"quoted,\tvalue\nภาษาไทย";
    foreach (['csv'=>'comma','tsv'=>'tab'] as $format=>$delimiter) {
      $csv = output_of(static function ($out) use ($db,$value,$format): void { ms_sqlite_export_result($db,'SELECT '.qs($db,$value).' AS value',$format,$out); });
      $file = $root . '/roundtrip.' . $format; file_put_contents($file,$csv);
      [$headers,$rows] = ms_import_parse_csv_file($file,$delimiter);
      same($headers,['value']); same($rows,[[$value]]);
    }
  });
  check('Grid plan and exports use filters, sort, pagination and no identity helpers', static function () use ($db): void {
    $_GET = ['table'=>'items','filter_col'=>['id'],'filter_op'=>['>='],'filter_val'=>['1'],'order_col'=>['id'],'order_dir'=>['DESC'],'limit'=>'1','p'=>'2'];
    $cols = table_columns($db,'items'); [$sql] = build_select_query($db,'items',$cols);
    [$plans] = explain_sql($db,$sql);
    same(array_column($plans[0]['fields'],'name'),['id','parent','notused','detail']);
    same((string)db_one($db,$sql)['id'],'3');
    $csv = output_of(static function ($out) use ($db,$sql,$cols): void { ms_sqlite_export_result($db,$sql,'csv',$out,array_column($cols,'COLUMN_NAME'),false); });
    same(strpos($csv,'id,name,value,amount,doubled')===0,true);
    same(strpos($csv,'__ms_'),false);
    [$all] = build_select_query($db,'items',$cols,null,null,true);
    same(count(db_all($db,$all)),4);
    $_GET = [];
  });
  check('SQL editor Explain never executes DELETE or trigger side effects', static function () use ($db): void {
    explain_sql($db,'DELETE FROM items'); explain_sql($db,"INSERT INTO items(name) VALUES ('should-not-exist')");
    same((string)db_one($db,'SELECT count(*) AS n FROM items')['n'],'4');
  });
  check('Mapped import handles defaults, NULL/empty values and generated rejection', static function () use ($db): void {
    $result = import_rows($db,'items',['id','name','value'],[['110','imported',null],['111','empty-text','']]);
    same([$result['success'],$result['errors']],[2,0]);
    same((string)db_one($db,'SELECT amount FROM items WHERE id=110')['amount'],'7');
    same(db_one($db,'SELECT value FROM items WHERE id=110')['value'],null);
    same(db_one($db,'SELECT value FROM items WHERE id=111')['value'],'');
    rejects(static function () use ($db): void { import_rows($db,'items',['id','doubled'],[['112','2']]); });
  });
  check('Updates require exactly one non-NULL match', static function () use ($db): void {
    $result = import_rows($db,'no_key',['value'],[['same']],'update','value');
    same([$result['success'],$result['errors']],[0,1]);
    $result = import_rows($db,'items',['id','name'],[['110','updated'],['999','missing'],[null,'null-key']],'update','id');
    same([$result['success'],$result['errors']],[1,2]);
  });
  check('Upsert preserves composite keys and omitted values', static function () use ($db): void {
    $result = import_rows($db,'composite',['a','b','value'],[['key','1','new'],['key','2','second']],'upsert');
    same([$result['success'],$result['errors']],[2,0]);
    same(db_one($db,"SELECT value FROM composite WHERE a='key' AND b=1")['value'],'new');
    $result = import_rows($db,'items',['id','name'],[['110','upserted']],'upsert');
    same($result['success'],1); same((string)db_one($db,'SELECT amount FROM items WHERE id=110')['amount'],'7');
  });
  check('Failed import row rolls back RAISE(FAIL) trigger effects', static function () use ($db): void {
    $db->run("CREATE TRIGGER reject_bad AFTER INSERT ON items WHEN new.name='bad' BEGIN INSERT INTO audit VALUES (999); SELECT RAISE(FAIL,'rejected by trigger'); END");
    $result = import_rows($db,'items',['id','name'],[['120','bad'],['121','good']]);
    same([$result['success'],$result['errors']],[1,1]);
    same(db_one($db,'SELECT id FROM items WHERE id=120'),null);
    same(db_one($db,'SELECT id FROM audit WHERE id IN (120,999)'),null);
    $entry = $_SESSION['ms_import_errors'][$result['error_token']];
    [$headers,$rows] = ms_import_parse_csv_file($entry['path'],'comma');
    same(array_slice($rows[0],0,3),['2','120','bad']);
    same(strpos($rows[0][3],'rejected by trigger')!==false,true);
  });
  check('Transaction-level import failure rolls back all earlier successes', static function () use ($db): void {
    $db->run("CREATE TRIGGER abort_all AFTER INSERT ON items WHEN new.name='abort' BEGIN SELECT RAISE(ROLLBACK,'abort entire import'); END");
    rejects(static function () use ($db): void { import_rows($db,'items',['id','name'],[['130','earlier'],['131','abort']]); });
    same(db_one($db,'SELECT id FROM items WHERE id IN (130,131)'),null);
    same($db->sqlite()->inTransaction(),false);
  });
  check('Import and result-export tokens cannot cross SQLite files', static function () use ($root,$target): void {
    $file = $root.'/token.csv'; file_put_contents($file,"id,name\n200,token\n");
    $import = ms_import_create_preview($file,'token.csv','auto'); $export = register_sql_result_export('SELECT * FROM items');
    $login = $_SESSION['ms_login']; $_SESSION['ms_login']['path'] = $target;
    try { rejects(static function () use ($import): void { ms_import_entry($import); }); rejects(static function () use ($export): void { sql_result_export_entry($export); }); }
    finally { $_SESSION['ms_login'] = $login; }
  });
  check('Built-in diagnostics pass without modifying or opening the current DB', static function () use ($source,$root): void {
    $before = hash_file('sha256',$source); $login = $_SESSION['ms_login'];
    // An unavailable active DB proves the runner never connects to it.
    $_SESSION['ms_login']['path'] = $root.'/unavailable.sqlite';
    try {
      $report = ms_diagnostics_run();
      if (!$report['blocking_passed']) throw new RuntimeException(json_encode($report));
      same(count($report['results']),10); same($report['cleanup']['status'],'pass');
      same(file_exists($report['database']),false); same(is_dir(dirname($report['database'])),false);
      same(hash_file('sha256',$source),$before);
    } finally { @unlink(ms_diagnostics_report_file()); $_SESSION['ms_login'] = $login; }
  });
} finally {
  $db->close(); $restored->close();
  foreach (['ms_imports','ms_import_errors'] as $key) foreach ($_SESSION[$key] ?? [] as $entry) if (is_file($entry['path'])) unlink($entry['path']);
  foreach (scandir($root) as $name) if ($name!=='.' && $name!=='..' && is_file($root.'/'.$name)) unlink($root.'/'.$name);
  rmdir($root);
}
echo "$checks checks, $failures failures\n";
exit($failures ? 1 : 0);
