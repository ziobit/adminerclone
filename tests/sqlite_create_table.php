<?php
/** Guided SQLite DDL regressions. All databases live in a disposable private directory. */
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
function definition(string $name, array $columns = [], array $options = []): array {
  return ['name'=>$name, 'columns'=>$columns ?: [['name'=>'id','type'=>'INTEGER','primary'=>'1']]] + $options;
}
function create_table(MSDatabase $db, array $spec): void {
  $preview = ms_sqlite_create_preview($db,$spec);
  ms_sqlite_create_execute($db,$preview['token'],true);
}

$root = sys_get_temp_dir() . '/ms-create-test-' . bin2hex(random_bytes(8));
mkdir($root,0700);
putenv('MS_SQLITE_ROOT=' . $root);
$hash = password_hash('test-only',PASSWORD_DEFAULT);
putenv('MS_SQLITE_PASSWORD_HASH=' . $hash);
$db = null; $other = null;
try {
  foreach (['source','other'] as $name) {
    $native = new PDO('sqlite:' . $root . '/' . $name . '.sqlite');
    $native->exec('CREATE TABLE bootstrap(id INTEGER PRIMARY KEY, value TEXT)');
    $native->exec("INSERT INTO bootstrap VALUES (1,'untouched')");
    $native = null;
  }
  $_SESSION['ms_login'] = ['engine'=>'sqlite','path'=>$root . '/source.sqlite','sqlite_auth'=>hash('sha256',$hash)];
  $_SESSION['ms_db'] = 'main';
  $db = new MSSQLiteDatabase($root . '/source.sqlite');
  $other = new MSSQLiteDatabase($root . '/other.sqlite');
  $GLOBALS['db'] = $db;
  check('Preview compiles SQL without changing schema or data', static function () use ($db): void {
    $before = db_all($db,'SELECT * FROM sqlite_master');
    $version = db_one($db,'PRAGMA schema_version');
    $preview = ms_sqlite_create_preview($db,definition('preview_only'));
    same(strpos($preview['sql'],'CREATE TABLE "preview_only"'),0);
    same(db_all($db,'SELECT * FROM sqlite_master'),$before);
    same(db_one($db,'PRAGMA schema_version'),$version);
    same(db_one($db,'SELECT value FROM bootstrap')['value'],'untouched');
  });
  check('Confirmation required; token is single-use', static function () use ($db): void {
    $preview = ms_sqlite_create_preview($db,definition('confirmed'));
    rejects(static function () use ($db,$preview): void { ms_sqlite_create_execute($db,$preview['token'],false); });
    same(table_exists($db,'confirmed'),false);
    same(ms_sqlite_create_execute($db,$preview['token'],true),'confirmed');
    rejects(static function () use ($db,$preview): void { ms_sqlite_create_execute($db,$preview['token'],true); });
    $db->run('INSERT INTO confirmed DEFAULT VALUES');
    same((string)db_one($db,'SELECT id FROM confirmed')['id'],'1');
  });
  check('Previews are scoped to a canonical database file', static function () use ($db,$other): void {
    $preview = ms_sqlite_create_preview($db,definition('scoped'));
    rejects(static function () use ($other,$preview): void { ms_sqlite_create_execute($other,$preview['token'],true); });
    same(table_exists($other,'scoped'),false);
  });
  check('Expired and unknown preview tokens are rejected', static function () use ($db): void {
    $preview = ms_sqlite_create_preview($db,definition('expired'));
    $_SESSION['ms_sqlite_create_previews'][$preview['token']]['expires'] = time() - 1;
    foreach ([$preview['token'],'unknown'] as $token) rejects(static function () use ($db,$token): void { ms_sqlite_create_execute($db,$token,true); });
  });
  check('Concurrent creation cannot replace a table or its rows', static function () use ($db): void {
    $preview = ms_sqlite_create_preview($db,definition('race'));
    $db->run('CREATE TABLE race(value TEXT)'); $db->run("INSERT INTO race VALUES ('keep')");
    rejects(static function () use ($db,$preview): void { ms_sqlite_create_execute($db,$preview['token'],true); });
    same(db_one($db,'SELECT value FROM race')['value'],'keep');
  });
  check('Quoted Unicode identifiers and literal defaults cannot inject SQL', static function () use ($db): void {
    $table = 'ไทย " ; DROP TABLE bootstrap; --';
    $value = "O'Brien\n'); DROP TABLE bootstrap; --";
    create_table($db,definition($table,[['name'=>'a"b','type'=>'TEXT','default_kind'=>'text','default_value'=>$value]]));
    $db->run('INSERT INTO ' . qi($table) . ' DEFAULT VALUES');
    same(db_one($db,'SELECT * FROM ' . qi($table))['a"b'],$value);
    same(table_exists($db,'bootstrap'),true);
  });
  check('Numeric, empty, NULL, date and expression defaults preserve semantics', static function () use ($db): void {
    create_table($db,definition('defaults',[
      ['name'=>'big','type'=>'INTEGER','default_kind'=>'number','default_value'=>'9223372036854775807'],
      ['name'=>'empty','type'=>'TEXT','default_kind'=>'text','default_value'=>''],
      ['name'=>'nil','type'=>'BLOB','default_kind'=>'null'],
      ['name'=>'today','type'=>'TEXT','default_kind'=>'CURRENT_DATE'],
      ['name'=>'calc','type'=>'REAL','default_kind'=>'expression','default_value'=>'(2 + 3) * 1.5'],
      ['name'=>'amount','type'=>'NUMERIC','default_kind'=>'number','default_value'=>'-1.25e2']
    ]));
    $db->run('INSERT INTO defaults DEFAULT VALUES');
    $r = db_one($db,'SELECT CAST(big AS TEXT) AS big,"empty",nil,today,calc,amount FROM defaults');
    same($r['big'],'9223372036854775807'); same($r['empty'],''); same($r['nil'],null); same(strlen($r['today']),10); same((float)$r['calc'],7.5); same((float)$r['amount'],-125.0);
  });
  check('Column order and composite primary-key order follow the submitted order', static function () use ($db): void {
    create_table($db,definition('composite',[
      ['name'=>'b','type'=>'TEXT','primary'=>'1'], ['name'=>'a','type'=>'INTEGER','primary'=>'1'], ['name'=>'value','type'=>'TEXT']
    ],['without_rowid'=>'1']));
    same(array_column(table_columns($db,'composite'),'COLUMN_NAME'),['b','a','value']);
    same(primary_columns($db,'composite'),['b','a']);
    $db->run("INSERT INTO composite VALUES ('x',1,'ok')");
    rejects(static function () use ($db): void { $db->run("INSERT INTO composite VALUES ('x',1,'duplicate')"); });
    rejects(static function () use ($db): void { $db->run("INSERT INTO composite VALUES (NULL,2,'null')"); });
  });
  check('AUTOINCREMENT does not reuse deleted IDs', static function () use ($db): void {
    create_table($db,definition('sequence',[['name'=>'id','type'=>'INTEGER','primary'=>'1','auto_increment'=>'1']]));
    $db->run('INSERT INTO sequence DEFAULT VALUES'); $db->run('DELETE FROM sequence'); $db->run('INSERT INTO sequence DEFAULT VALUES');
    same((string)db_one($db,'SELECT id FROM sequence')['id'],'2');
  });
  check('NOT NULL, UNIQUE, CHECK and NOCASE constraints are enforced', static function () use ($db): void {
    create_table($db,definition('constraints',[
      ['name'=>'name','type'=>'TEXT','unique'=>'1','not_null'=>'1','collation'=>'NOCASE'],
      ['name'=>'qty','type'=>'INTEGER','check'=>'qty >= 0 AND qty < 100']
    ]));
    $db->run("INSERT INTO constraints VALUES ('First',1)");
    foreach (["('first',2)","(NULL,2)","('other',-1)"] as $values) rejects(static function () use ($db,$values): void { $db->run('INSERT INTO constraints VALUES ' . $values); });
  });
  check('Foreign keys and CASCADE actions are enforced', static function () use ($db): void {
    create_table($db,definition('children',[['name'=>'parent','type'=>'INTEGER','ref_table'=>'bootstrap','ref_column'=>'id','on_delete'=>'CASCADE','on_update'=>'CASCADE']]));
    $db->run('INSERT INTO children VALUES (1)');
    rejects(static function () use ($db): void { $db->run('INSERT INTO children VALUES (999)'); });
    $db->run('UPDATE bootstrap SET id=2 WHERE id=1');
    same((string)db_one($db,'SELECT parent FROM children')['parent'],'2');
    $db->run('UPDATE bootstrap SET id=1 WHERE id=2');
  });
  check('Self references and UNIQUE parent keys are accepted', static function () use ($db): void {
    create_table($db,definition('tree',[['name'=>'id','type'=>'INTEGER','primary'=>'1'],['name'=>'parent','type'=>'INTEGER','ref_table'=>'tree','ref_column'=>'id','on_delete'=>'SET NULL']]));
    $db->run('INSERT INTO tree VALUES (1,NULL),(2,1)'); $db->run('DELETE FROM tree WHERE id=1');
    same(db_one($db,'SELECT parent FROM tree')['parent'],null);
    create_table($db,definition('unique_child',[['name'=>'parent','type'=>'TEXT','ref_table'=>'constraints','ref_column'=>'name']]));
    $db->run("INSERT INTO unique_child VALUES ('FIRST')");
  });
  check('Missing, nonunique and mismatched-collation FK targets are rejected', static function () use ($db): void {
    $db->run('CREATE UNIQUE INDEX custom_collation ON bootstrap(value COLLATE NOCASE)');
    foreach ([['missing','id'],['bootstrap','missing'],['bootstrap','value']] as $target) rejects(static function () use ($db,$target): void {
      ms_sqlite_create_preview($db,definition('bad_fk',[['name'=>'parent','type'=>'TEXT','ref_table'=>$target[0],'ref_column'=>$target[1]]]));
    });
  });
  check('Removed FK parent requires a new valid preview', static function () use ($db): void {
    $db->run('CREATE TABLE transient_parent(id INTEGER PRIMARY KEY)');
    $p = ms_sqlite_create_preview($db,definition('orphan',[['name'=>'parent','type'=>'INTEGER','ref_table'=>'transient_parent','ref_column'=>'id']]));
    $db->run('DROP TABLE transient_parent');
    rejects(static function () use ($db,$p): void { ms_sqlite_create_execute($db,$p['token'],true); });
    same(table_exists($db,'orphan'),false);
  });
  check('STRICT validation uses SQLite version, not PHP version', static function () use ($db): void {
    $spec = definition('strict_table',[['name'=>'n','type'=>'INTEGER'],['name'=>'any_value','type'=>'ANY']],['strict'=>'1']);
    rejects(static function () use ($spec): void { ms_sqlite_create_definition($spec,'3.36.0'); });
    if (version_compare($db->server_info,'3.37.0','>=')) {
      create_table($db,$spec);
      rejects(static function () use ($db): void { $db->run("INSERT INTO strict_table VALUES ('not a number',NULL)"); });
      $db->run("INSERT INTO strict_table VALUES (2,'000123')");
      same(db_one($db,'SELECT any_value FROM strict_table')['any_value'],'000123');
      create_table($db,definition('strict_without_rowid',[],['strict'=>'1','without_rowid'=>'1']));
    }
  });
  $bad = [
    'empty name'=>definition(''), 'reserved name'=>definition('SQLite_custom'),
    'empty columns'=>['name'=>'bad','columns'=>[]], 'malformed columns'=>['name'=>'bad','columns'=>'invalid'],
    'nested value'=>definition('bad',[['name'=>['x'],'type'=>'TEXT']]),
    'duplicate names'=>definition('bad',[['name'=>'A','type'=>'TEXT'],['name'=>'a','type'=>'TEXT']]),
    'NUL identifier'=>definition("bad\0name"), 'control identifier'=>definition("bad\nname"),
    'injected type'=>definition('bad',[['name'=>'n','type'=>'TEXT); DROP TABLE bootstrap; --']]),
    'invalid number'=>definition('bad',[['name'=>'n','type'=>'TEXT','default_kind'=>'number','default_value'=>'1); DROP TABLE bootstrap; --']]),
    'NULL with NOT NULL'=>definition('bad',[['name'=>'n','type'=>'TEXT','not_null'=>'1','default_kind'=>'null']]),
    'invalid collation'=>definition('bad',[['name'=>'n','type'=>'TEXT','collation'=>'BINARY; DROP TABLE bootstrap']]),
    'multiple auto columns'=>definition('bad',[['name'=>'a','type'=>'INTEGER','primary'=>'1','auto_increment'=>'1'],['name'=>'b','type'=>'INTEGER','primary'=>'1','auto_increment'=>'1']]),
    'auto without PK'=>definition('bad',[['name'=>'n','type'=>'INTEGER','auto_increment'=>'1']]),
    'auto noninteger'=>definition('bad',[['name'=>'n','type'=>'TEXT','primary'=>'1','auto_increment'=>'1']]),
    'auto without rowid'=>definition('bad',[['name'=>'n','type'=>'INTEGER','primary'=>'1','auto_increment'=>'1']],['without_rowid'=>'1']),
    'without rowid missing PK'=>definition('bad',[['name'=>'n','type'=>'TEXT']],['without_rowid'=>'1']),
    'strict numeric'=>definition('bad',[['name'=>'n','type'=>'NUMERIC']],['strict'=>'1']),
    'partial FK'=>definition('bad',[['name'=>'n','type'=>'INTEGER','ref_table'=>'bootstrap']]),
    'invalid FK action'=>definition('bad',[['name'=>'n','type'=>'INTEGER','ref_table'=>'bootstrap','ref_column'=>'id','on_delete'=>'CASCADE; DROP TABLE bootstrap']]),
    'SET NULL with NOT NULL'=>definition('bad',[['name'=>'n','type'=>'INTEGER','not_null'=>'1','ref_table'=>'bootstrap','ref_column'=>'id','on_delete'=>'SET NULL']])
  ];
  foreach ($bad as $label=>$spec) check('Reject ' . $label, static function () use ($db,$spec): void { rejects(static function () use ($db,$spec): void { ms_sqlite_create_preview($db,$spec); }); });
  foreach (['1); DROP TABLE bootstrap; --','1) , injected TEXT CHECK (1','1 -- tail',"1 /* comment */",'?',':name','(1',"readfile('/tmp/forbidden')","\"load_extension\"('x')"] as $expression) {
    check('Reject unsafe expression: ' . $expression, static function () use ($db,$expression): void {
      foreach (['check','default_value'] as $field) rejects(static function () use ($db,$expression,$field): void {
        ms_sqlite_create_preview($db,definition('injection',[['name'=>'n','type'=>'INTEGER','default_kind'=>$field === 'default_value' ? 'expression' : 'none',$field=>$expression]]));
      });
    });
  }
  check('SQLite parser rejects invalid CHECK and nonconstant defaults during preview', static function () use ($db): void {
    foreach ([['check'=>'missing > 0'],['default_kind'=>'expression','default_value'=>'unknown_function()'],['check'=>'1 +']] as $extra) rejects(static function () use ($db,$extra): void {
      ms_sqlite_create_preview($db,definition('parse_error',[['name'=>'n','type'=>'INTEGER'] + $extra]));
    });
    same(table_exists($db,'parse_error'),false);
  });
  check('Limit is 50 columns, no silently dropped input', static function () use ($db): void {
    $columns = [];
    for ($i=0;$i<51;$i++) $columns[] = ['name'=>'c'.$i,'type'=>'TEXT'];
    rejects(static function () use ($db,$columns): void { ms_sqlite_create_preview($db,definition('too_many',$columns)); });
    array_pop($columns); create_table($db,definition('fifty',$columns)); same(count(table_columns($db,'fifty')),50);
  });
  check('Preview cache is bounded and supports multiple tabs', static function () use ($db): void {
    $tokens = [];
    for ($i=0;$i<6;$i++) $tokens[] = ms_sqlite_create_preview($db,definition('pending'.$i))['token'];
    same(count($_SESSION['ms_sqlite_create_previews']),5);
    rejects(static function () use ($db,$tokens): void { ms_sqlite_create_pending($db,$tokens[0]); });
    ms_sqlite_create_execute($db,$tokens[4],true); ms_sqlite_create_execute($db,$tokens[5],true);
  });
  check('Existing SQLite schema and data remain intact', static function () use ($db): void {
    same(db_one($db,'SELECT value FROM bootstrap WHERE id=1')['value'],'untouched');
    same((string)db_one($db,'PRAGMA foreign_keys')['foreign_keys'],'1');
  });
} finally {
  $GLOBALS['db'] = null; $db = null; $other = null;
  foreach (glob($root . '/*') ?: [] as $path) unlink($path);
  rmdir($root);
}
echo "$checks checks, $failures failures\n";
exit($failures ? 1 : 0);
