#!/usr/bin/env python3
"""Test the real updater downloader against a local fixture; never install an update."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import os
from pathlib import Path
import re
import subprocess
import tempfile
import threading

php = os.environ.get('PHP_BINARY', 'php')
repository = Path(__file__).resolve().parents[1]
fixture = b'<?php /* local updater download fixture */'

class Handler(BaseHTTPRequestHandler):
  def do_GET(self):
    self.send_response(200)
    self.send_header('Content-Type', 'text/plain')
    self.send_header('Content-Length', str(len(fixture)))
    self.end_headers()
    self.wfile.write(fixture)

  def log_message(self, *args):
    pass

server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
thread = threading.Thread(target=server.serve_forever, daemon=True)
thread.start()
try:
  with tempfile.TemporaryDirectory(prefix='ms-updater-') as temporary:
    app = Path(temporary) / 'index.php'
    source = (repository / 'index.php').read_text()
    source, replacements = re.subn(r"const MS_UPDATE_URL = '[^']+';", "const MS_UPDATE_URL = 'http://127.0.0.1:%d/source.php';" % server.server_port, source)
    assert replacements == 1, 'Updater URL constant must be replaced exactly once'
    app.write_text(source)
    program = '''
      require $argv[1];
      ini_set('session.save_path', sys_get_temp_dir());
      if (($argv[3] === 'curl') !== function_exists('curl_init')) throw new RuntimeException('Unexpected downloader transport');
      define('MS_LIBRARY_ONLY', true); require $argv[2];
      echo ms_update_download();
    '''
    for transport in ['curl', 'stream']:
      command = [php, '-d', 'error_reporting=-1', '-d', 'display_errors=1', '-d', 'allow_url_fopen=1']
      if transport == 'curl':
        command += ['-d', 'allow_url_fopen=0']  # Ensure the cURL path cannot silently fall back.
      else:
        command += ['-d', 'disable_functions=curl_init']
      result = subprocess.run(command + ['-r', program, str(repository / 'tests/deprecations.php'), str(app), transport], capture_output=True, timeout=30)
      assert result.returncode == 0, result.stderr.decode(errors='replace')
      assert result.stdout == fixture, result.stdout.decode(errors='replace')
      assert not result.stderr, result.stderr.decode(errors='replace')
      print('PASS updater ' + transport + ' download without PHP diagnostics')
finally:
  server.shutdown()
  server.server_close()
  thread.join(timeout=5)
