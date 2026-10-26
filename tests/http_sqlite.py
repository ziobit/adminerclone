#!/usr/bin/env python3
"""Exercise a copied single-file deployment over HTTP using disposable fixtures."""
import base64
import http.cookiejar
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

php = os.environ.get('PHP_BINARY', 'php')
php_command = [php, '-d', 'error_reporting=-1', '-d', 'display_errors=1', '-d', 'log_errors=1', '-d', 'html_errors=0']
source = Path(__file__).resolve().parents[1] / 'index.php'
checks = 0

def check(condition, message):
  global checks
  checks += 1
  if not condition:
    raise AssertionError(message)
  print('PASS ' + message)

with tempfile.TemporaryDirectory(prefix='ms-http-') as temporary:
  root = Path(temporary)
  public = root / 'public'
  databases = root / 'databases'
  sessions = root / 'sessions'
  public.mkdir()
  databases.mkdir()
  sessions.mkdir()
  php_command += ['-d', 'session.save_path=' + str(sessions)]
  app = public / 'index.php'
  shutil.copyfile(source, app)
  env = dict(os.environ, MS_SQLITE_ROOT=str(databases))
  fixture = databases / 'sample.sqlite'
  init = '''
    ini_set('session.save_path',sys_get_temp_dir());
    define('MS_LIBRARY_ONLY',true); require $argv[1];
    ms_update_cache_write(['checked_at'=>time(),'status'=>'current','remote_version'=>MS_VERSION]);
    $db = new PDO('sqlite:'.$argv[2]);
    $db->exec('CREATE TABLE items(id INTEGER PRIMARY KEY, name TEXT NOT NULL, qty NUMERIC DEFAULT 7, note TEXT, payload BLOB)');
    $db->exec("INSERT INTO items(name,note) VALUES ('first','one'),('second','two'),('third','three')");
    $db->exec('CREATE TABLE duplicates(value TEXT)');
    $db->exec("INSERT INTO duplicates VALUES ('same'),('same')");
    $db->exec('CREATE VIEW item_names AS SELECT id,name FROM items');
    echo password_hash('test-admin-password',PASSWORD_DEFAULT);
  '''
  result = subprocess.run(php_command + ['-r', init, str(app), str(fixture)], check=True, capture_output=True, text=True)
  if result.stderr or re.search(r'(Deprecated|Warning|Notice|Fatal error):', result.stdout):
    raise AssertionError('PHP startup diagnostics: ' + result.stderr + result.stdout)
  env['MS_SQLITE_PASSWORD_HASH'] = result.stdout.strip()
  with socket.socket() as probe:
    probe.bind(('127.0.0.1', 0))
    port = probe.getsockname()[1]
  base = 'http://127.0.0.1:' + str(port) + '/'
  jar = http.cookiejar.CookieJar()
  opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
  log = open(root / 'server.log', 'w+')
  server = subprocess.Popen(php_command + ['-S', '127.0.0.1:' + str(port), '-t', str(public)], env=env, stdout=log, stderr=log)
  def request(query='', data=None):
    payload = None if data is None else urllib.parse.urlencode(data, doseq=True).encode()
    try:
      with opener.open(base + query, payload, timeout=15) as response:
        status, body = response.status, response.read().decode('utf-8', errors='replace')
    except urllib.error.HTTPError as error:
      status, body = error.code, error.read().decode('utf-8', errors='replace')
    if re.search(r'(Deprecated|Warning|Notice|Fatal error):', body):
      raise AssertionError('PHP diagnostics in HTTP response: ' + body[:2000])
    return status, body
  def token(html):
    return re.search(r'name="csrf" value="([a-f0-9]+)"', html).group(1)
  def rows():
    command = '$d=new PDO("sqlite:".$argv[1]);echo json_encode($d->query("SELECT * FROM items ORDER BY id")->fetchAll(PDO::FETCH_ASSOC));'
    return json.loads(subprocess.run(php_command + ['-r',command,str(fixture)],check=True,capture_output=True,text=True).stdout)
  try:
    for attempt in range(100):
      try:
        status, html = request()
        break
      except (OSError, urllib.error.URLError):
        if server.poll() is not None:
          raise RuntimeError('PHP server failed to start')
        time.sleep(0.05)
    check(status == 200 and 'Database engine' in html, 'Login exposes database-engine selection')
    csrf = token(html)
    status, html = request(data={'action':'login','csrf':csrf,'engine':'sqlite','sqlite_file':'sample.sqlite','password':'wrong'})
    check('SQLite login failed' in html and 'Log out' not in html, 'Incorrect SQLite password is rejected')
    status, html = request(data={'action':'login','csrf':csrf,'engine':'sqlite','sqlite_file':'sample.sqlite','password':'test-admin-password'})
    check(status == 200 and 'SQLite: sample.sqlite' in html and 'Log out' in html, 'SQLite password connects to configured file')
    csrf = token(html)
    check('href="?page=users"' not in html and 'href="?page=processes"' not in html, 'MySQL server administration is absent')
    for page in ['database','sql','settings','global_search','structure&table=items','select&table=items','select&table=items&view_mode=cards','row&table=items&mode=insert']:
      status, html = request('?page=' + page)
      check(status == 200 and 'Operation failed' not in html and 'Warning:' not in html and 'Fatal error' not in html, 'Render page ' + page)
    status, html = request('?page=settings', {'action':'save_profile_settings','csrf':csrf,'selectRows':'50','sqlRows':'1000'})
    check(status == 200 and 'Settings saved for profile' in html, 'SQLite preserves the existing settings save action')
    status, html = request('?page=select&table=items&filter_col[]=qty&filter_op[]=%3D&filter_val[]=7&order_col[]=id&order_dir[]=DESC&limit=1&p=2')
    check(status == 200 and 'second' in html, 'HTTP browse applies filter, sorting and pagination')
    status, html = request('?page=row&table=items&mode=insert', {'action':'save_row','csrf':csrf,'value[id]':'','value[name]':"O'Brien ภาษาไทย",'value[qty]':'ignored','use_default[qty]':'1','value[note]':'inserted','is_null[payload]':'1'})
    check(status == 200 and rows()[-1]['name'] == "O'Brien ภาษาไทย" and float(rows()[-1]['qty']) == 7, 'HTTP insert preserves Unicode, quotes and default SQL')
    identity = base64.b64encode(b'a:1:{s:2:"id";i:4;}').decode()
    status, html = request('?page=row&table=items&mode=edit&id=' + urllib.parse.quote(identity), {'action':'save_row','csrf':csrf,'identity':identity,'value[id]':'4','value[name]':'changed','value[qty]':'9.5','value[note]':'edited','keep_blob[payload]':'1'})
    check(status == 200 and rows()[-1]['name'] == 'changed' and float(rows()[-1]['qty']) == 9.5, 'HTTP row update uses the original primary key')
    status, html = request('?page=select&table=items', {'action':'bulk_update','csrf':csrf,'row_id[]':identity,'column':'note','operation':'append','bulk_value':' + bulk'})
    check(status == 200 and rows()[-1]['note'] == 'edited + bulk', 'HTTP bulk update uses SQLite concatenation')
    status, html = request('?page=sql', {'action':'run_sql','csrf':csrf,'sql':'SELECT name,qty FROM items WHERE id=:id','param_name[]':'id','param_type[]':'number','param_value[]':'4'})
    check(status == 200 and 'changed' in html and '9.5' in html and 'Operation failed' not in html, 'HTTP SQL parameters and result rendering')
    status, html = request('?page=sql', {'action':'run_sql','csrf':csrf,'sql':'SELECT missing_column FROM items'})
    check('no such column' in html, 'HTTP SQL errors are shown')
    status, html = request('?page=select&table=items', {'action':'delete_row','csrf':csrf,'identity':identity})
    check(status == 200 and len(rows()) == 3, 'HTTP delete removes exactly one row')
    status, html = request('?page=select&table=duplicates')
    check(status == 200 and 'data-ms-column="_rowid_"' not in html, 'Implicit row identity stays out of visible table cells')
    row_ids = re.findall(r'name="row_id\[\]" value="([^"]+)"', html)
    check(len(set(row_ids)) == 2, 'Identical no-PK rows have different HTTP identities')
    status, html = request('?page=select&table=duplicates', {'action':'delete_rows','csrf':csrf,'row_id[]':row_ids[0]})
    check(status == 200, 'HTTP delete selected accepts implicit rowid')
    status, html = request('?page=select&table=item_names')
    check(status == 200 and 'title="Edit row"' not in html, 'SQLite views are browse-only')
    view_id = re.search(r'href="([^\"]*mode=view[^\"]*)"',html).group(1).replace('&amp;','&')
    status, html = request(view_id)
    check(status == 200 and 'View row: item_names' in html, 'Read-only view rows can be opened')
    for page in ['users','processes','variables','routines','events','repair_recipes','export','import']:
      status, html = request('?page=' + page)
      check(status == 500 and 'not yet available for SQLite' in html, 'Direct MySQL-only route guarded: ' + page)
    status, html = request('?page=database', {'action':'drop_database','csrf':csrf,'confirm_name':'main'})
    check('not yet available for SQLite' in html and len(rows()) == 3, 'Direct unsupported administrative POST is guarded')
    status, html = request('?page=select&table=items', {'action':'delete_rows','row_id[]':identity})
    check(status == 403 and len(rows()) == 3, 'CRUD requires a valid CSRF token')
    status, html = request('?page=sql', {'action':'run_sql','csrf':csrf,'sql':"ATTACH '/tmp/forbidden.sqlite' AS other"})
    check('other database files through SQL is disabled' in html, 'SQL editor refuses filesystem escape')
    status, html = request(data={'action':'logout','csrf':csrf})
    check(status == 200 and 'Database engine' in html and 'Log out' not in html, 'Logout returns to engine selection')
    log.flush()
    log.seek(0)
    check(re.search(r'(Deprecated|Warning|Notice|Fatal error):', log.read()) is None, 'HTTP flow emits no PHP diagnostics with E_ALL')
    print(str(checks) + ' HTTP checks passed')
  except Exception:
    log.flush()
    log.seek(0)
    print(log.read()[-12000:])
    raise
  finally:
    server.terminate()
    server.wait(timeout=10)
    log.close()
    # All application runtime files are scoped to this disposable copied path.
    import hashlib
    prefix = 'mysql-studio-' + hashlib.sha1(str(app).encode()).hexdigest() + '-'
    for runtime in Path(tempfile.gettempdir()).glob(prefix + '*'):
      runtime.unlink()
