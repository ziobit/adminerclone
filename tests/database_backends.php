<?php
/** Run against disposable databases only. No dependencies beyond PHP extensions. */
declare(strict_types=1);
require __DIR__ . '/deprecations.php';
ini_set('session.save_path', sys_get_temp_dir());
define('MS_LIBRARY_ONLY', true);
require dirname(__DIR__) . '/index.php';

$failures = 0;
$checks = 0;
function check(string $name, callable $fn): void {
  global $failures, $checks;
  $checks++;
  try { $fn(); echo "PASS $name\n"; }
  catch (Throwable $e) { $failures++; echo "FAIL $name: " . $e->getMessage() . "\n"; }
}
function same($actual, $expected): void {
  // PDO_SQLite on PHP 7.4 returns numeric result cells as strings, like mysqli.
  if (is_string($actual) && (is_int($expected) || is_float($expected)) && $actual === (string)$expected) return;
  if ($actual !== $expected) throw new RuntimeException('Expected ' . var_export($expected, true) . ', got ' . var_export($actual, true));
}
function rejects(callable $fn): void {
  try { $fn(); } catch (Throwable $e) { return; }
  throw new RuntimeException('Expected operation to fail.');
}
function captured(callable $fn): string {
  ob_start();
  try { $fn(); return (string)ob_get_contents(); }
  finally { ob_end_clean(); }
}

$engine = $argv[1] ?? 'sqlite';
if ($engine === 'mysql') {
  $_SESSION['ms_login'] = ['host'=>getenv('MS_TEST_HOST') ?: '127.0.0.1','port'=>(int)(getenv('MS_TEST_PORT') ?: 3306),'socket'=>getenv('MS_TEST_SOCKET') ?: '', 'user'=>getenv('MS_TEST_USER') ?: 'root','password'=>getenv('MS_TEST_PASSWORD') ?: ''];
  $legacyKey = hash('sha256', $_SESSION['ms_login']['host'] . "\0" . $_SESSION['ms_login']['port'] . "\0" . $_SESSION['ms_login']['socket'] . "\0" . $_SESSION['ms_login']['user']);
  check('Legacy MySQL profile key preserved', static function () use ($legacyKey): void { same(ms_server_config_key(), $legacyKey); });
  $db = connect_db(false);
  check('Native mysqli connection retained', static function () use ($db): void { same($db->engine, 'mysql'); });
  $database = 'ms_backend_test_' . bin2hex(random_bytes(6));
  $db->query('CREATE DATABASE ' . qi($database) . ' CHARACTER SET utf8mb4');
  try {
    $_SESSION['ms_db'] = $database; $db->select_db($database);
    $db->query('CREATE TABLE sample (id BIGINT PRIMARY KEY AUTO_INCREMENT, label VARCHAR(80), payload BLOB) ENGINE=InnoDB');
    check('MySQL prepared insert', static function () use ($db): void { $db->run('INSERT INTO sample(label) VALUES (?)', ["O\x27Brien 🐘"]); same((int)$db->affected_rows, 1); });
    check('MySQL metadata', static function () use ($db): void { same(primary_columns($db, 'sample'), ['id']); same(count(table_columns($db, 'sample')), 3); same(ms_table_list($db)[0]['TABLE_NAME'], 'sample'); });
    check('MySQL prepared update and select', static function () use ($db): void { $db->run('UPDATE sample SET label=? WHERE id=?', ['updated',1]); same(db_one($db, 'SELECT label FROM sample WHERE id=?', [1])['label'], 'updated'); });
    check('MySQL sorting/filter/pagination', static function () use ($db): void {
      $_GET = ['table'=>'sample','filter_col'=>['label'],'filter_op'=>['contains'],'filter_val'=>['date'],'order_col'=>['id'],'order_dir'=>['DESC'],'limit'=>'1'];
      [$sql] = build_select_query($db,'sample',table_columns($db,'sample')); same(count(db_all($db,$sql)),1);
    });
    check('MySQL SQL execution returns rows and errors', static function () use ($db): void { [$sets] = execute_sql($db,'SELECT 7 AS value; SELECT 9 AS value'); same((string)$sets[1]['rows'][0][0],'9'); rejects(static function () use ($db): void { execute_sql($db,'SELECT missing FROM sample'); }); });
    check('MySQL transaction rollback', static function () use ($db): void { $db->begin_transaction(); $db->query('DELETE FROM sample'); $db->rollback(); same((int)db_one($db,'SELECT COUNT(*) AS n FROM sample')['n'],1); });
    check('MySQL prepared delete', static function () use ($db): void { $db->run('DELETE FROM sample WHERE id=?',[1]); same((int)$db->affected_rows,1); });
    check('Rejected import CSV retains source values and errors', static function () use ($db): void {
      $headers = ['id', 'label'];
      $rows = [['2', "valid ภาษาไทย"], ['bad-id', 'Rejected "quoted", C:\\folder']];
      $upload = tempnam(sys_get_temp_dir(), 'ms-import-test-');
      $before = $_POST;
      try {
        file_put_contents($upload, json_encode(array_map(static function (array $row) use ($headers): array { return array_combine($headers, $row); }, $rows)));
        $token = ms_import_create_preview($upload, 'compatibility.json', 'auto');
        $_POST = ['import_table'=>'sample', 'mapping'=>$headers, 'import_mode'=>'insert'];
        $result = ms_import_execute_rows($db, $token);
        same($result['success'], 1);
        same($result['errors'], 1);
        same(db_one($db, 'SELECT label FROM sample WHERE id=2')['label'], $rows[0][1]);
        $entry = $_SESSION['ms_import_errors'][$result['error_token']];
        [$actualHeaders, $actualRows] = ms_import_parse_csv_file($entry['path'], 'comma');
        same($actualHeaders, ['source_row', 'id', 'label', 'error']);
        same(array_slice($actualRows[0], 0, 3), ['3', $rows[1][0], $rows[1][1]]);
        same($actualRows[0][3] !== '', true);
      } finally {
        unlink($upload);
        $_POST = $before;
        foreach (['ms_imports', 'ms_import_errors'] as $key) {
          foreach ($_SESSION[$key] ?? [] as $entry) if (is_file($entry['path'])) unlink($entry['path']);
          unset($_SESSION[$key]);
        }
      }
    });
    check('Existing MySQL diagnostic regression suite', static function (): void {
      $report = ms_diagnostics_run();
      $failed = array_filter($report['results'], static function (array $r): bool { return $r['status'] !== 'pass'; });
      if (!$report['blocking_passed']) throw new RuntimeException(json_encode(array_values($failed),JSON_UNESCAPED_SLASHES));
      echo '  Embedded cases: ' . count($report['results']) . " passed\n";
    });
  } finally {
    $db->query('DROP DATABASE ' . qi($database)); $db->close();
  }
} elseif ($engine === 'sqlite') {
  if (!class_exists('SQLite3')) throw new RuntimeException('SQLite3 extension required.');
  $root = sys_get_temp_dir() . '/ms-sqlite-test-' . bin2hex(random_bytes(6));
  mkdir($root, 0700);
  putenv('MS_SQLITE_ROOT=' . $root);
  $hash = password_hash('test-only-password',PASSWORD_DEFAULT);
  putenv('MS_SQLITE_PASSWORD_HASH=' . $hash);
  $file = $root . '/fixture.sqlite';
  $fixture = new SQLite3($file);
  $fixture->exec('CREATE TABLE sample (id INTEGER PRIMARY KEY, name TEXT NOT NULL, amount NUMERIC DEFAULT 2.5, payload BLOB, doubled NUMERIC GENERATED ALWAYS AS (amount * 2) STORED)');
  $fixture->exec('CREATE TABLE composite (b TEXT NOT NULL, a INTEGER NOT NULL, value TEXT, PRIMARY KEY(a,b)) WITHOUT ROWID');
  $fixture->exec('CREATE TABLE duplicates (value TEXT)');
  $fixture->exec('CREATE TABLE nullable_pk (k TEXT PRIMARY KEY, value TEXT)');
  $fixture->exec('CREATE TABLE descending_pk (id INTEGER PRIMARY KEY DESC, value TEXT)');
  $fixture->exec('CREATE TABLE shadowed (rowid TEXT, _rowid_ TEXT, oid TEXT)');
  $fixture->exec('CREATE TABLE child (id INTEGER PRIMARY KEY, parent_id INTEGER REFERENCES sample(id))');
  $fixture->exec('CREATE TABLE strange ("a""b" TEXT, "x`y" TEXT)');
  $fixture->exec('CREATE TABLE "has WITHOUT ROWID text" ("literal" TEXT DEFAULT \'WITHOUT ROWID\')');
  $fixture->exec('CREATE VIEW sample_view AS SELECT id,name FROM sample');
  $fixture->close();
  $_SESSION['ms_login'] = ['engine'=>'sqlite','path'=>$file,'sqlite_auth'=>hash('sha256',$hash),'user'=>'SQLite administrator'];
  $_SESSION['ms_db'] = 'main';
  $db = connect_db();
  $GLOBALS['db'] = $db;
  try {
    check('Canonical private file connection', static function () use ($file): void { same(ms_sqlite_path('fixture.sqlite'),realpath($file)); });
    check('SQLite profile isolated from MySQL', static function () use ($file): void { same(ms_server_config_key(),hash('sha256',"sqlite\0" . $file)); });
    foreach (['../outside.sqlite',':memory:','file:fixture.sqlite','https://host/db','missing.sqlite',"fixture.sqlite\0suffix"] as $path) check('Reject file path ' . json_encode($path),static function () use ($path): void { rejects(static function () use ($path): void { ms_sqlite_path($path); }); });
    check('Reject a non-database file', static function () use ($root): void { file_put_contents($root.'/fake.sqlite','not a SQLite database'); rejects(static function (): void { ms_sqlite_path('fake.sqlite'); }); });
    check('Reject escaping symlink', static function () use ($root): void { symlink(__FILE__,$root.'/escape.sqlite'); rejects(static function (): void { ms_sqlite_path('escape.sqlite'); }); });
    check('Reject database in document root', static function () use ($root): void { $_SERVER['DOCUMENT_ROOT']=$root; try { rejects(static function (): void { ms_sqlite_path('fixture.sqlite'); }); } finally { unset($_SERVER['DOCUMENT_ROOT']); } });
    check('SQLite foreign keys enabled', static function () use ($db): void { same(db_one($db,'PRAGMA foreign_keys')['foreign_keys'],1); });
    check('SQLite metadata and affinity', static function () use ($db): void { $c=array_column(table_columns($db,'sample'),null,'COLUMN_NAME'); same($c['id']['SQLITE_ROWID_ALIAS'],true); same($c['amount']['SQLITE_AFFINITY'],'NUMERIC'); same($c['amount']['COLUMN_DEFAULT'],'2.5'); same($c['doubled']['EXTRA'],'GENERATED'); });
    check('Composite primary-key order and WITHOUT ROWID', static function () use ($db): void { same(primary_columns($db,'composite'),['a','b']); });
    check('Nullable primary key uses rowid', static function () use ($db): void { same(primary_columns($db,'nullable_pk'),['_rowid_']); });
    check('INTEGER PRIMARY KEY DESC is not an auto ID', static function () use ($db): void { $c=table_columns($db,'descending_pk'); same($c[0]['SQLITE_ROWID_ALIAS'],false); });
    check('WITHOUT ROWID text in identifiers/defaults does not alter identity', static function () use ($db): void { same(primary_columns($db,'has WITHOUT ROWID text'),['_rowid_']); });
    check('Ordinary nullable composite keys fall back to rowid', static function () use ($db): void { $db->run('CREATE TABLE nullable_composite(a TEXT,b TEXT,PRIMARY KEY(a,b))'); same(primary_columns($db,'nullable_composite'),['_rowid_']); });
    check('Fully shadowed rowid is browse-only', static function () use ($db): void { same(primary_columns($db,'shadowed'),[]); rejects(static function () use ($db): void { ms_sqlite_where($db,'shadowed',['rowid'=>'x']); }); });
    check('Views are inspected and protected from writes', static function () use ($db): void { same(ms_table_meta($db,'sample_view')['TABLE_TYPE'],'VIEW'); same(count(table_columns($db,'sample_view')),2); rejects(static function () use ($db): void { ms_sqlite_save_row($db,'sample_view',['value'=>['id'=>1,'name'=>'bad']]); }); });
    check('Quoted identifiers round-trip', static function () use ($db): void { $db->run('INSERT INTO '.qi('strange').' ('.qi('a"b').','.qi('x`y').') VALUES (?,?)',['quote','tick']); same(db_one($db,'SELECT * FROM strange')['a"b'],'quote'); });
    check('Prepared insert with UTF-8, quotes, defaults, generated column', static function () use ($db): void { ms_sqlite_save_row($db,'sample',['value'=>['id'=>'','name'=>"O\x27Brien 🐘",'amount'=>'ignored','payload'=>'bytes','doubled'=>'999'],'use_default'=>['amount'=>1]]); $row=db_one($db,'SELECT * FROM sample'); same($row['id'],1); same($row['name'],"O\x27Brien 🐘"); same($row['amount'],2.5); same($row['doubled'],5); });
    check('Prepared BLOB and embedded NUL values', static function () use ($db): void { $db->run('INSERT INTO sample(name,payload) VALUES (?,?)',["a\0b","\0\xff'"],[1=>true]); $row=db_one($db,'SELECT name,hex(payload) AS b,typeof(payload) AS t FROM sample WHERE id=2'); same($row['name'],"a\0b"); same($row['b'],'00FF27'); same($row['t'],'blob'); });
    check('SQLite literal quoting preserves NUL text', static function () use ($db): void { same(db_one($db,'SELECT '.qs($db,"a\0b").' AS value')['value'],"a\0b"); });
    check('Prepared update preserves payload', static function () use ($db): void { ms_sqlite_save_row($db,'sample',['identity'=>encode_identity(['id'=>1]),'value'=>['id'=>'1','name'=>'updated','amount'=>'4.25'],'keep_blob'=>['payload'=>1]]); $r=db_one($db,'SELECT * FROM sample WHERE id=1'); same($r['doubled'],8.5); same($r['payload'],'bytes'); });
    check('SQL expression and NULL row options', static function () use ($db): void { ms_sqlite_save_row($db,'sample',['identity'=>encode_identity(['id'=>1]),'value'=>['id'=>'1','name'=>'expr','amount'=>'2+3'],'expression'=>['amount'=>1],'is_null'=>['payload'=>1]]); $r=db_one($db,'SELECT * FROM sample WHERE id=1'); same($r['amount'],5); same($r['payload'],null); });
    check('SQLite dynamic types are not constrained by MySQL widths', static function () use ($db): void { $db->run('CREATE TABLE affinity (small TINYINT, limited VARCHAR(2), val NUMERIC)'); ms_sqlite_save_row($db,'affinity',['value'=>['small'=>'1234567890123','limited'=>'long text','val'=>'text is allowed']]); $r=db_one($db,'SELECT * FROM affinity'); same($r['small'],1234567890123); same($r['limited'],'long text'); same($r['val'],'text is allowed'); });
    check('Full signed 64-bit integer primary keys', static function () use ($db): void { ms_sqlite_save_row($db,'sample',['value'=>['id'=>'9223372036854775807','name'=>'large','amount'=>'0'],'is_null'=>['payload'=>1]]); same((string)db_one($db,'SELECT id FROM sample WHERE name=\'large\'')['id'],'9223372036854775807'); });
    check('Reject out-of-range rowid alias', static function () use ($db): void { rejects(static function () use ($db): void { ms_sqlite_save_row($db,'sample',['value'=>['id'=>'9223372036854775808','name'=>'bad']]); }); });
    check('Prepared statements prevent injection', static function () use ($db): void { $db->run('INSERT INTO sample(name) VALUES (?)',["x'); DROP TABLE sample; --"]); same(table_exists($db,'sample'),true); });
    check('Missing identity cannot update arbitrary rows', static function () use ($db): void { rejects(static function () use ($db): void { ms_sqlite_save_row($db,'sample',['identity'=>encode_identity([]),'value'=>['name'=>'bad']]); }); });
    check('No-PK duplicate rows have distinct identities', static function () use ($db): void { $db->run("INSERT INTO duplicates VALUES ('same'),('same')"); $_GET=['table'=>'duplicates']; [$sql]=build_select_query($db,'duplicates',table_columns($db,'duplicates')); $r=db_all($db,$sql); same(count($r),2); same($r[0]['_rowid_']!==$r[1]['_rowid_'],true); same(ms_sqlite_delete_rows($db,'duplicates',[encode_identity(['_rowid_'=>$r[0]['_rowid_']])]),1); same(count(db_all($db,'SELECT * FROM duplicates')),1); });
    check('Composite-key update and delete', static function () use ($db): void { $db->run('INSERT INTO composite(a,b,value) VALUES (?,?,?)',[2,'key','old']); ms_sqlite_save_row($db,'composite',['identity'=>encode_identity(['a'=>2,'b'=>'key']),'value'=>['a'=>'2','b'=>'key','value'=>'new']]); same(db_one($db,'SELECT value FROM composite')['value'],'new'); same(ms_sqlite_delete_rows($db,'composite',[encode_identity(['a'=>2,'b'=>'key'])]),1); });
    check('Typed SQLite keys distinguish identical TEXT and BLOB bytes', static function () use ($db): void {
      $db->run('CREATE TABLE dynamic_keys(k NOT NULL PRIMARY KEY, value TEXT) WITHOUT ROWID');
      $db->run('INSERT INTO dynamic_keys VALUES (?,?)',['same','text']);
      $db->run('INSERT INTO dynamic_keys VALUES (?,?)',['same','blob'],[0=>true]);
      $_GET=['table'=>'dynamic_keys']; $columns=table_columns($db,'dynamic_keys');
      [$sql]=build_select_query($db,'dynamic_keys',$columns); $rows=db_all($db,$sql);
      foreach($rows as $row)if($row['value']==='blob')$id=ms_sqlite_row_identity($columns,primary_columns($db,'dynamic_keys'),$row);
      same(ms_sqlite_delete_rows($db,'dynamic_keys',[encode_identity($id)]),1);
      same(db_one($db,'SELECT value FROM dynamic_keys')['value'],'text');
    });
    check('REAL primary-key identities retain full precision on PHP 7.4', static function () use ($db): void {
      $db->run("INSERT INTO dynamic_keys VALUES (1.2345678901234567,'real1'),(1.234567890123456,'real2')");
      $_GET=['table'=>'dynamic_keys']; $columns=table_columns($db,'dynamic_keys'); [$sql]=build_select_query($db,'dynamic_keys',$columns);
      foreach(db_all($db,$sql) as $row)if($row['value']==='real1')$id=ms_sqlite_row_identity($columns,primary_columns($db,'dynamic_keys'),$row);
      same(ms_sqlite_delete_rows($db,'dynamic_keys',[encode_identity($id)]),1);
      same(db_one($db,"SELECT value FROM dynamic_keys WHERE value='real2'")['value'],'real2');
    });
    check('Unchanged typeless integers retain their storage class', static function () use ($db): void {
      $db->run('CREATE TABLE typeless(value, note TEXT)'); $db->run("INSERT INTO typeless VALUES (42,'old')");
      ms_sqlite_save_row($db,'typeless',['identity'=>encode_identity(['_rowid_'=>1]),'value'=>['value'=>'42','note'=>'new']]);
      same(db_one($db,'SELECT typeof(value) AS t FROM typeless')['t'],'integer');
    });
    check('Foreign-key metadata and enforcement', static function () use ($db): void { same(ms_foreign_keys($db,'child')[0]['REFERENCED_COLUMN_NAME'],'id'); rejects(static function () use ($db): void { $db->run('INSERT INTO child(parent_id) VALUES (?)',[-42]); }); });
    check('Filtering, sorting and pagination', static function () use ($db): void { $_GET=['table'=>'sample','filter_col'=>['name'],'filter_op'=>['contains'],'filter_val'=>['e'],'order_col'=>['id'],'order_dir'=>['DESC'],'limit'=>'1','p'=>'2']; [$sql,$count]=build_select_query($db,'sample',table_columns($db,'sample')); same(count(db_all($db,$sql)),1); same((int)db_one($db,$count)['n']>=2,true); });
    check('Invalid filter/sort identifiers are ignored', static function () use ($db): void { $_GET=['filter_col'=>['id; DROP TABLE sample'],'filter_op'=>['='],'filter_val'=>['1'],'order_col'=>['evil']]; [$sql]=build_select_query($db,'sample',table_columns($db,'sample')); same(strpos($sql,'DROP'),false); same(count(db_all($db,$sql))>0,true); });
    check('Multi-statement SQL, CTEs, empty SELECT metadata', static function () use ($db): void { [$sets]=execute_sql($db,'WITH n(x) AS (SELECT 8) SELECT x FROM n; SELECT name FROM sample WHERE 0'); same($sets[0]['rows'][0][0],8); same($sets[1]['fields'][0]->name,'name'); same($sets[1]['count'],0); });
    check('Empty prepared SELECT retains column names', static function () use ($db): void { $r=$db->run('SELECT name,amount FROM sample WHERE id=?',[-123]); same(array_column($r->fetch_fields(),'name'),['name','amount']); same($r->num_rows,0); });
    check('SQL result display cap', static function () use ($db): void { [$sets]=execute_sql($db,'SELECT * FROM sample',false,1); same($sets[0]['shown'],1); same($sets[0]['capped'],true); });
    check('SQLite statement splitting and trigger bodies', static function () use ($db): void { execute_sql($db,"CREATE TABLE log(message TEXT); CREATE TRIGGER sample_log AFTER INSERT ON sample BEGIN INSERT INTO log VALUES (CASE WHEN NEW.name IS NULL THEN 'null;' ELSE NEW.name END); INSERT INTO log VALUES ('second'); END; INSERT INTO sample(name) VALUES ('trigger');"); same(count(db_all($db,'SELECT * FROM log')),2); });
    check('Backslash and bracket quoting in SQLite SQL parameters', static function () use ($db): void { $sql=ms_expand_sql_parameters($db,"SELECT 'back\\' AS [a:b], :value AS value--no space\n",['value'=>['type'=>'text','value'=>"O'Brien"]]); same(db_one($db,$sql)['value'],"O'Brien"); });
    check('SQL errors propagate', static function () use ($db): void { rejects(static function () use ($db): void { db_all($db,'SELECT missing FROM sample'); }); });
    check('Prepared multi-statement text is refused', static function () use ($db): void { rejects(static function () use ($db): void { $db->run('SELECT 1; DROP TABLE sample'); }); });
    foreach (["ATTACH DATABASE '/tmp/escape.sqlite' AS other",'DETACH main',"VACUUM INTO '/tmp/escape.sqlite'","PRAGMA temp_store_directory='/tmp'",'PRAGMA writable_schema=ON','EXPLAIN PRAGMA writable_schema=ON',"EXPLAIN QUERY PLAN PRAGMA temp_store_directory='/tmp'","SELECT load_extension('/tmp/evil')","SELECT 'writefile'('/tmp/evil','data')"] as $sql) check('Block SQLite file escape ' . $sql,static function () use ($db,$sql): void { same($db->query($sql),false); });
    check('Harmless function-name text is allowed', static function () use ($db): void { same(db_one($db,"SELECT 'writefile' AS value")['value'],'writefile'); });
    check('Read-only PRAGMAs remain usable', static function () use ($db): void { same(db_one($db,'PRAGMA integrity_check')['integrity_check'],'ok'); });
    check('Transaction rollback and FK delete atomicity', static function () use ($db): void { $db->run('INSERT INTO child(parent_id) VALUES (?)',[1]); rejects(static function () use ($db): void { ms_sqlite_delete_rows($db,'sample',[encode_identity(['id'=>2]),encode_identity(['id'=>1])]); }); same(db_one($db,'SELECT id FROM sample WHERE id=2')['id'],2); });
    check('Global search uses SQLite functions', static function () use ($db): void { $r=ms_global_search_run($db,['term'=>'expr','mode'=>'starts','columns'=>['sample'=>['name']]]); same($r[0]['total'],1); });
    check('MySQL-only pages and actions are guarded', static function (): void { same(ms_sqlite_page_supported('users'),false); same(ms_sqlite_action_supported('drop_database'),false); same(ms_sqlite_action_supported('save_row'),true); });
    check('SQLite sidebar hides server administration', static function (): void { $_GET=['page'=>'database']; $html=captured(static function (): void { render_sidebar(); }); same(strpos($html,'href="?page=users"'),false); same(strpos($html,'href="?page=sql"')!==false,true); });
    check('SQLite database and structure pages render', static function () use ($db): void { $_GET=['table'=>'sample']; same(strpos(captured(static function () use ($db): void { page_database($db); }),'sample_view')!==false,true); same(strpos(captured(static function () use ($db): void { page_structure($db); }),'NUMERIC')!==false,true); });
    check('Existing table browse page renders SQLite', static function () use ($db): void { $_GET=['page'=>'select','table'=>'sample']; $html=captured(static function () use ($db): void { page_select($db); }); same(strpos($html,'Insert row')!==false,true); });
    check('Existing row editor renders SQLite', static function () use ($db): void { $_GET=['page'=>'row','mode'=>'edit','table'=>'sample','id'=>encode_identity(['id'=>1])]; same(strpos(captured(static function () use ($db): void { page_row($db); }),'Save row')!==false,true); });
    check('SQL editor renders SQLite metadata', static function () use ($db): void { $_GET=['page'=>'sql']; same(strpos(captured(static function () use ($db): void { page_sql($db,null,0); }),'sample_view')!==false,true); });
    check('Settings can hide actual SQLite primary-key columns', static function () use ($db): void { $counts=ms_column_view_hide_primary_keys($db,'main'); same($counts[0]>0,true); });
    check('Rotating administrator credentials revokes existing connections', static function (): void { putenv('MS_SQLITE_PASSWORD_HASH=changed'); try { rejects(static function (): void { connect_db(); }); } finally { [, $unused]=ms_sqlite_config(); } });
  } finally {
    $db->close();
    foreach (glob($root.'/*') ?: [] as $path) unlink($path);
    rmdir($root);
  }
} else { throw new RuntimeException('Usage: php tests/database_backends.php sqlite|mysql'); }
echo "$checks checks, $failures failures\n";
exit($failures ? 1 : 0);
