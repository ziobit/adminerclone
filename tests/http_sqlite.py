#!/usr/bin/env python3
"""Exercise a copied single-file deployment over HTTP using disposable fixtures."""
import base64
import csv
import hashlib
import html as html_module
import http.cookiejar
import io
import json
import os
from pathlib import Path
import re
import shutil
import socket
import sqlite3
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile

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
  def upload(data, field, name, content):
    boundary = 'ms-regression-' + os.urandom(12).hex()
    parts = []
    for key, value in data.items():
      parts.append(('--' + boundary + '\r\nContent-Disposition: form-data; name="' + key + '"\r\n\r\n' + str(value) + '\r\n').encode())
    parts.append(('--' + boundary + '\r\nContent-Disposition: form-data; name="' + field + '"; filename="' + name + '"\r\nContent-Type: application/octet-stream\r\n\r\n').encode() + content + b'\r\n')
    parts.append(('--' + boundary + '--\r\n').encode())
    req = urllib.request.Request(base + '?page=import', b''.join(parts), {'Content-Type': 'multipart/form-data; boundary=' + boundary})
    try:
      with opener.open(req, timeout=30) as response:
        return response.status, response.read().decode()
    except urllib.error.HTTPError as error:
      return error.code, error.read().decode()
  def download(params):
    with opener.open(base + '?' + urllib.parse.urlencode(params, doseq=True), timeout=30) as response:
      check('attachment;' in response.headers.get('Content-Disposition', ''), 'Export has attachment headers')
      return response.read()
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
    for page in ['database','sql','settings','global_search','diagnostics','import','export','structure&table=items','select&table=items','select&table=items&view_mode=cards','row&table=items&mode=insert']:
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
    for page in ['users','processes','variables','routines','events','repair_recipes']:
      status, html = request('?page=' + page)
      check(status == 500 and 'not yet available for SQLite' in html, 'Direct MySQL-only route guarded: ' + page)
    status, html = request('?page=database', {'action':'drop_database','csrf':csrf,'confirm_name':'main'})
    check('not yet available for SQLite' in html and len(rows()) == 3, 'Direct unsupported administrative POST is guarded')
    status, html = request('?page=select&table=items', {'action':'delete_rows','row_id[]':identity})
    check(status == 403 and len(rows()) == 3, 'CRUD requires a valid CSRF token')
    status, html = request('?page=sql', {'action':'run_sql','csrf':csrf,'sql':"ATTACH '/tmp/forbidden.sqlite' AS other"})
    check('other database files through SQL is disabled' in html, 'SQL editor refuses filesystem escape')

    query = {'page':'select','table':'items','filter_col[]':['qty'],'filter_op[]':['='],'filter_val[]':['7'],'order_col[]':['id'],'order_dir[]':['DESC'],'limit':'1','p':'2'}
    status, html = request('?' + urllib.parse.urlencode(dict(query, explain='1'), doseq=True))
    plan_sql = html_module.unescape(re.search(r'data-ms-explain-sql>(.*?)</pre>', html, re.S).group(1))
    check(status == 200 and 'EXPLAIN QUERY PLAN' in html and 'detail' in html and 'WHERE' in plan_sql and 'DESC' in plan_sql and re.search(r'LIMIT\s+1\s*,\s*1', plan_sql), 'Grid Explain displays the exact filtered/sorted paginated query')
    status, html = request('?page=sql', {'action':'run_sql','csrf':csrf,'sql':'DELETE FROM items','sql_submit':'explain'})
    check(status == 200 and 'EXPLAIN QUERY PLAN' in html and len(rows()) == 3, 'SQL editor Explain is non-mutating')
    for filtered in [False, True]:
      for scope in ['all', 'page']:
        for format in ['csv','tsv','sql']:
          for zipped in [False, True]:
            params = dict(query, download='select_result', export_scope=scope, format=format, zip='1' if zipped else '0')
            if filtered:
              params.update({'filter_col[]':['id'],'filter_val[]':['2']})
              params['p'] = '1'
            raw = download(params)
            if zipped:
              with zipfile.ZipFile(io.BytesIO(raw)) as archive:
                check(len(archive.namelist()) == 1 and archive.namelist()[0].endswith('.' + format), 'ZIP contains exactly the chosen export format')
                raw = archive.read(archive.namelist()[0])
            expected = 1 if filtered or scope == 'page' else 3
            if format == 'sql':
              memory = sqlite3.connect(':memory:')
              try:
                memory.executescript(raw.decode())
                actual = memory.execute('SELECT * FROM query_result').fetchall()
                headers = [column[1] for column in memory.execute('PRAGMA table_info(query_result)')]
              finally:
                memory.close()
            else:
              parsed = list(csv.reader(io.StringIO(raw.decode('utf-8-sig')), delimiter='\t' if format == 'tsv' else ','))
              headers, actual = parsed[0], parsed[1:]
            check(len(actual) == expected and headers == ['id','name','qty','note','payload'], f'Export {format}, ZIP={zipped}, filtered={filtered}, scope={scope} preserves rows and excludes identity metadata')
            if scope == 'page':
              check(str(actual[0][0]) == '2', 'Export current page matches grid ordering and offset')
    raw = download({'download':'export','format':'sql','tables[]':['items','duplicates','item_names'],'structure':'1','data':'1','drop':'1'})
    memory = sqlite3.connect(':memory:')
    try:
      memory.executescript(raw.decode())
      check(memory.execute('SELECT count(*) FROM item_names').fetchone()[0] == 3, 'Database SQL download restores tables and views')
    finally:
      memory.close()
    status, html = request('?page=sql', {'action':'run_sql','csrf':csrf,'sql':'SELECT id,name FROM items ORDER BY id'})
    export_token = re.search(r'name="token" value="([a-f0-9]{48})"', html).group(1)
    raw = download({'download':'sql_result','format':'csv','token':export_token})
    check(len(list(csv.reader(io.StringIO(raw.decode('utf-8-sig'))))) == 4, 'SQL editor result export works through its session token')

    request('?page=sql', {'action':'run_sql','csrf':csrf,'sql':'CREATE TABLE transfers(id INTEGER PRIMARY KEY, label TEXT NOT NULL UNIQUE)'} )
    status, html = upload({'action':'import_preview','csrf':csrf}, 'import_file', 'transfers.csv', 'id,label\n1,"hello, ภาษาไทย"\n2,second\n3,second\n'.encode())
    import_token = re.search(r'name="import_token" value="([a-f0-9]{32})"', html).group(1)
    check(status == 200 and '2. Map and import' in html and 'hello, ภาษาไทย' in html, 'CSV upload shows a mapping preview without writing rows')
    status, html = request('?page=import', {'action':'import_execute','csrf':csrf,'import_token':import_token,'import_table':'transfers','mapping[]':['id','label'],'import_mode':'insert'})
    check(status == 200 and '2 successful row(s)' in html and '1 rejected' in html, 'Mapped SQLite CSV import reports successful and rejected rows')
    error_token = re.search(r'download=import_errors&amp;token=([a-f0-9]{32})',html).group(1)
    raw = download({'download':'import_errors','token':error_token})
    rejected = list(csv.reader(io.StringIO(raw.decode('utf-8-sig'))))
    check(rejected[1][:3] == ['4','3','second'] and 'UNIQUE' in rejected[1][-1], 'Rejected rows download includes source row and constraint error')
    status, html = upload({'action':'sqlite_restore','csrf':csrf}, 'restore_file','restore.sql', b'CREATE TABLE restored(id INTEGER); INSERT INTO restored VALUES (42);')
    check('Confirm that the SQL file' in html, 'SQL restore requires server-side explicit confirmation')
    status, html = upload({'action':'sqlite_restore','csrf':csrf,'restore_confirm':'1'}, 'restore_file','restore.sql', b'CREATE TABLE restored(id INTEGER); INSERT INTO restored VALUES (42);')
    check(status == 200 and 'SQLite restore committed successfully' in html, 'Confirmed SQL restore commits through the normal release UI')
    status, html = upload({'action':'sqlite_restore','csrf':csrf,'restore_confirm':'1'}, 'restore_file','restore.sql', b'DELETE FROM restored; INSERT INTO missing VALUES (0);')
    check('no such table' in html, 'Broken SQL restore reports failure')
    status, html = request('?page=sql', {'action':'run_sql','csrf':csrf,'sql':'SELECT id FROM restored'})
    check('42' in html, 'Broken restore leaves previous data intact')

    status, html = request('?page=diagnostics')
    warning = 'These are regression tests. They do not touch the current DB, but you are not supposed to run them, but you can if you want. Continue?'
    check(warning in html and 'Run diagnostics' in html, 'Normal-release SQLite Diagnostics retains the requested warning')
    before = hashlib.sha256(fixture.read_bytes()).hexdigest()
    status, html = request('?page=diagnostics', {'action':'run_diagnostics','csrf':csrf})
    check(status == 200 and 'release gate: PASS' in html and '10 passed' in html, 'SQLite built-in Diagnostics passes over HTTP')
    check(before == hashlib.sha256(fixture.read_bytes()).hexdigest() and not list(databases.glob('ms-diagnostics-*')), 'Diagnostics leaves the current DB unchanged and removes its disposable directory')

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
