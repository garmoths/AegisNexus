"""One-command native runtime: build, migrate, Redis, workers, Beat and API."""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
PYTHON = ROOT / '.venv/bin/python'
STATE = ROOT / 'data/local'
RUN = STATE / 'run'
LOGS = STATE / 'logs'
CHILDREN = []


def say(message):
    print(message, flush=True)


def execute(command, cwd=ROOT, env=None):
    subprocess.run([str(c) for c in command], cwd=cwd, env=env, check=True)


def fingerprint(paths):
    digest = hashlib.sha256()
    for path in sorted(paths):
        digest.update(str(path.relative_to(ROOT)).encode())
        digest.update(path.read_bytes())
    return digest.hexdigest()


def setup():
    if not shutil.which('npm') or not shutil.which('node'):
        raise RuntimeError('Node.js 22.12+ gerekli. macOS: brew install node | Linux: nodejs.org üzerinden Node.js LTS kurun.')
    version = subprocess.check_output(['node', '-p', 'process.versions.node'], text=True).strip()
    major, minor, *_ = map(int, version.split('.'))
    if not ((major == 20 and minor >= 19) or (major == 22 and minor >= 12) or major >= 24):
        raise RuntimeError('Node.js 22.12+ LTS gerekli; bulunan sürüm: ' + version)
    stamp = ROOT / '.venv/.aegis-requirements'
    expected = fingerprint([ROOT / 'requirements.txt'])
    if not stamp.exists() or stamp.read_text() != expected:
        say('Python bağımlılıkları kontrol ediliyor…')
        execute([PYTHON, '-m', 'pip', '--disable-pip-version-check', 'install', '-r', ROOT / 'requirements.txt'])
        execute([PYTHON, '-m', 'pip', 'check'])
        stamp.write_text(expected)
    if not shutil.which('redis-server'):
        say('Yerel kuyruk için Redis kuruluyor (Docker gerekmez)…')
        if sys.platform == 'darwin' and shutil.which('brew'):
            execute(['brew', 'install', 'redis'], env={**os.environ, 'HOMEBREW_NO_AUTO_UPDATE': '1'})
        elif sys.platform.startswith('linux') and shutil.which('apt-get'):
            prefix = [] if os.geteuid() == 0 else ['sudo']
            execute([*prefix, 'apt-get', 'update'])
            execute([*prefix, 'apt-get', 'install', '-y', 'redis-server'])
        else:
            raise RuntimeError('redis-server bulunamadı; işletim sisteminizin paket yöneticisiyle Redis kurun.')
    # Homebrew installs in its prefix; PATH may have been set before installation.
    if not shutil.which('redis-server'):
        raise RuntimeError('redis-server PATH üzerinde bulunamadı.')
    from dotenv import dotenv_values
    preferred_browser = os.getenv('AEGIS_CHROMIUM_PATH') or dotenv_values(ROOT / '.env').get('AEGIS_CHROMIUM_PATH')
    candidates = [preferred_browser or '']
    if sys.platform == 'darwin' and not preferred_browser:
        candidates += [str(Path('/Applications') / app / 'Contents/MacOS' / binary) for app, binary in
                       [('Google Chrome.app', 'Google Chrome'), ('Chromium.app', 'Chromium'), ('Microsoft Edge.app', 'Microsoft Edge')]]
        candidates += [str(p) for p in sorted(Path('/Applications/Burp Suite.app/Contents/Resources/app/burpbrowser').glob('*/Chromium.app/Contents/MacOS/Chromium'), reverse=True)]
    browser_ready = False
    for candidate in candidates:
        if candidate and not Path(candidate).is_file():
            continue
        try:
            check = subprocess.run([PYTHON, '-c',
                'import sys; from playwright.sync_api import sync_playwright; '
                'p=sync_playwright().start(); b=p.chromium.launch(headless=True, **({"executable_path":sys.argv[1]} if sys.argv[1] else {})); '
                'b.close(); p.stop()', candidate], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=25)
            if check.returncode == 0:
                browser_ready = True
                (STATE / 'chromium.path').write_text(candidate)
                say('URL analizi için Chromium hazır' + (': ' + candidate if candidate else '.'))
                break
        except subprocess.TimeoutExpired:
            continue
    if not browser_ready:
        say('URL analizinin Chromium tarayıcısı kuruluyor…')
        command = [PYTHON, '-m', 'playwright', 'install']
        if sys.platform.startswith('linux'):
            command.append('--with-deps')
        execute([*command, 'chromium'])
        (STATE / 'chromium.path').write_text('')
    front = ROOT / 'frontend-react'
    lock_hash = fingerprint([front / 'package.json', front / 'package-lock.json'])
    node_stamp = front / 'node_modules/.aegis-dependencies'
    if not node_stamp.exists() or node_stamp.read_text() != lock_hash:
        say('Frontend bağımlılıkları kontrol ediliyor…')
        execute(['npm', 'ci', '--no-fund', '--no-audit'], cwd=front)
        node_stamp.write_text(lock_hash)
    paths = [front / name for name in ('package.json', 'package-lock.json', 'vite.config.js', 'index.html')]
    paths += [p for directory in ('src', 'public') for p in (front / directory).rglob('*') if p.is_file()]
    build_hash = fingerprint(paths)
    build_stamp = front / 'dist/.aegis-build'
    if not build_stamp.exists() or build_stamp.read_text() != build_hash:
        say('Frontend derleniyor…')
        execute(['npm', 'run', 'build'], cwd=front)
        build_stamp.write_text(build_hash)
    if not (ROOT / '.env').exists():
        shutil.copyfile(ROOT / '.env.example', ROOT / '.env')
        (ROOT / '.env').chmod(0o600)
        say('.env oluşturuldu; harici API anahtarlarını ihtiyacınıza göre ekleyebilirsiniz.')


def environment():
    from dotenv import dotenv_values
    env = {**{k: v for k, v in dotenv_values(ROOT / '.env').items() if v is not None}, **os.environ}
    browser_path = STATE / 'chromium.path'
    if not env.get('AEGIS_CHROMIUM_PATH') and browser_path.exists() and browser_path.read_text().strip():
        env['AEGIS_CHROMIUM_PATH'] = browser_path.read_text().strip()
    for key, value in list(env.items()):
        if value in ('CHANGE_ME', 'YOUR_GEMINI_API_KEY_HERE'):
            env[key] = ''
    # The launcher owns this Redis instance. Ignore legacy container hostnames in .env.
    env['CELERY_BROKER_URL'] = 'redis+socket://' + str(RUN / 'redis.sock') + '?virtual_host=0'
    env['CELERY_RESULT_BACKEND'] = 'redis+socket://' + str(RUN / 'redis.sock') + '?virtual_host=1'
    env['DATABASE_URL'] = env.get('AEGIS_DATABASE_URL') or env.get('DATABASE_URL') or 'sqlite:///' + str(ROOT / 'data/aegis.db')
    env.update(PYTHONUNBUFFERED='1', PYTHONDONTWRITEBYTECODE='1', PYTHONPATH=str(ROOT),
               RUNTIME_DB_PATH=str(ROOT / 'data/runtime.db'), PDF_OUTPUT_DIR=str(ROOT / 'data/reports'), CELERY_TIMEZONE='Europe/Istanbul')
    return env


def spawn(name, command, env):
    log = open(LOGS / (name + '.log'), 'ab', buffering=0)
    os.chmod(log.name, 0o600)
    process = subprocess.Popen([str(c) for c in command], cwd=ROOT, env=env, stdin=subprocess.DEVNULL,
                               stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
    CHILDREN.append((name, process, log))
    return process


def check_children():
    for name, process, _ in CHILDREN:
        if process.poll() is not None:
            raise RuntimeError(f'{name} durdu (kod {process.returncode}). Log: {LOGS / (name + ".log")}')


def wait_until(check, label, timeout=60):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        check_children()
        try:
            if check():
                return
        except (OSError, ValueError):
            pass
        time.sleep(0.3)
    raise RuntimeError(label + ' zamanında hazır olmadı. Loglar: ' + str(LOGS))


def shutdown():
    say('\nAegisNexus kapatılıyor…')
    # Stop API/Beat first. Keep Redis alive while workers restore unacknowledged jobs.
    workers = [entry for entry in CHILDREN if entry[0] != 'redis']
    for _, process, _ in reversed(workers):
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGTERM)
    deadline = time.monotonic() + 30
    for _, process, _ in workers:
        try:
            process.wait(timeout=max(0, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
    for _, process, _ in CHILDREN:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
    for _, _, log in CHILDREN:
        log.close()
    (RUN / 'launcher.json').unlink(missing_ok=True)
    say('Tüm AegisNexus süreçleri kapandı.')


def main():
    parser = argparse.ArgumentParser(description='AegisNexus: Docker olmadan tek komutla çalıştır.')
    parser.add_argument('command', nargs='?', default='start', choices=['start', 'setup', 'status', 'stop'])
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--port', type=int, default=8000)
    parser.add_argument('--no-install', action='store_true', help='Kurulum/derlemeyi atla (önceden setup gerekir).')
    args = parser.parse_args()
    os.chdir(ROOT)
    RUN.mkdir(parents=True, exist_ok=True)
    LOGS.mkdir(parents=True, exist_ok=True)
    STATE.chmod(0o700)
    RUN.chmod(0o700)
    LOGS.chmod(0o700)
    with open(RUN / 'launcher.lock', 'a+') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            running = False
        except BlockingIOError:
            running = True
        if args.command in ('status', 'stop'):
            if not running:
                say('AegisNexus çalışmıyor.')
                return 0
            try:
                info = json.loads((RUN / 'launcher.json').read_text())
            except (OSError, ValueError):
                say('AegisNexus hazırlanıyor; kısa süre sonra tekrar deneyin.')
                return 1
            if args.command == 'status':
                say('AegisNexus çalışıyor: ' + info['url'])
            else:
                os.kill(info['pid'], signal.SIGTERM)
                say('Kapatma istendi; çalışan görevlerin kapanması en fazla 40 saniye sürebilir.')
            return 0
        if running:
            raise RuntimeError('Bu proje zaten çalışıyor. Durum: ./run.sh status | Kapat: ./run.sh stop')
        # A crashed older launch may have left its PID behind. Do not expose it
        # to stop/status while this new owner is still performing setup.
        (RUN / 'launcher.json').unlink(missing_ok=True)
        if not args.no_install:
            setup()
        if args.command == 'setup':
            say('Kurulum hazır. Başlatmak için: ./run.sh')
            return 0
        with socket.socket() as port_check:
            try:
                port_check.bind((args.host, args.port))
            except OSError as exc:
                raise RuntimeError(f'{args.host}:{args.port} kullanımda. Başka port: ./run.sh --port 8001') from exc
        if len(os.fsencode(RUN / 'redis.sock')) > 100:
            raise RuntimeError('Proje yolu Redis Unix soketi için çok uzun; projeyi daha kısa bir dizine taşıyın.')
        env = environment()
        say('Veritabanı migration işlemleri uygulanıyor…')
        execute([PYTHON, '-m', 'alembic', 'upgrade', 'head'], env=env)
        import redis
        client = redis.Redis(unix_socket_path=str(RUN / 'redis.sock'), socket_timeout=1)
        try:
            if client.ping():
                raise RuntimeError('Bu projeye ait Redis zaten açık. Önce eski başlatıcıyı kapatın.')
        except redis.ConnectionError:
            pass
        def interrupted(*_):
            raise KeyboardInterrupt
        signal.signal(signal.SIGTERM, interrupted)
        signal.signal(signal.SIGINT, interrupted)
        url_host = '127.0.0.1' if args.host == '0.0.0.0' else args.host
        url = f'http://{url_host}:{args.port}'
        (RUN / 'launcher.json').write_text(json.dumps({'pid': os.getpid(), 'url': url}))
        application = None
        try:
            spawn('redis', ['redis-server', '--port', '0', '--unixsocket', RUN / 'redis.sock', '--unixsocketperm', '700',
                            '--dir', STATE, '--appendonly', 'yes', '--appendfsync', 'everysec', '--save', '', '--daemonize', 'no'], env)
            def redis_ready():
                try:
                    return client.ping()
                except (redis.ConnectionError, redis.TimeoutError):
                    return False
            wait_until(redis_ready, 'Redis')
            client.close()
            say('Redis hazır. Celery workerları başlatılıyor…')
            celery = [PYTHON, '-m', 'celery', '-A', 'app.celery_app:celery_app']
            names = []
            for queue, concurrency in [('default', 2), ('phishing', 1)]:
                name = 'aegis-' + queue + '@' + socket.gethostname()
                names.append(name)
                worker_env = {**env, 'CELERY_WORKER_TYPE': queue}
                if sys.platform == 'darwin':
                    # Billiard uses spawn on macOS; Celery 5.5 needs its exec/spawn
                    # initializer to populate the fast task tracer in each child.
                    worker_env['FORKED_BY_MULTIPROCESSING'] = '1'
                spawn(queue, [*celery, 'worker', '-Q', queue, '-P', 'prefork', '-c', str(concurrency),
                              '-n', 'aegis-' + queue + '@%h', '--loglevel=info', '--without-gossip', '--without-mingle'],
                      worker_env)
            # Update this supervisor's config only; services already received their environment.
            os.environ.update(env)
            from app.celery_app import celery_app
            application = celery_app
            def workers_ready():
                replies = celery_app.control.ping(destination=names, timeout=0.5)
                return {next(iter(reply)) for reply in replies} >= set(names)
            wait_until(workers_ready, 'Celery workerları')
            from celery.exceptions import TimeoutError as TaskTimeout

            from app.workflow_tasks import runtime_probe
            for queue in ('default', 'phishing'):
                probe = runtime_probe.apply_async(queue=queue, expires=60)
                try:
                    # Ping checks only the parent; exercise a pool child as well.
                    result = probe.get(timeout=30)
                    if result != {'ok': True}:
                        raise RuntimeError(queue + ' görev kontrolü başarısız.')
                except TaskTimeout:
                    say(queue + ' kuyruğu meşgul; hazır worker heartbeat ile doğrulandı, kontrol işi bekliyor.')
                except Exception as exc:
                    raise RuntimeError(queue + ' worker görev çalıştıramıyor: ' + str(exc)) from exc
                finally:
                    probe.forget()
                    del probe
            spawn('beat', [*celery, 'beat', '--loglevel=info', '--schedule', STATE / 'celerybeat-schedule',
                           '--pidfile', RUN / 'beat.pid'], env)
            spawn('api', [PYTHON, '-m', 'uvicorn', 'app.main:app', '--host', args.host, '--port', str(args.port)], env)
            def api_ready():
                with urlopen(url + '/ready', timeout=2) as response:
                    return response.status == 200
            wait_until(api_ready, 'API')
            say(f'\nAegisNexus hazır: {url}\nAPI belgeleri: {url}/docs\nLoglar: {LOGS}\nKapat: Ctrl+C veya başka terminalde ./run.sh stop\n')
            while True:
                check_children()
                time.sleep(1)
        except KeyboardInterrupt:
            return 0
        finally:
            # A second Ctrl+C must not interrupt child cleanup.
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
            signal.signal(signal.SIGINT, signal.SIG_IGN)
            if application is not None:
                # Close pub/sub before Redis. AsyncResult callbacks otherwise
                # attempt to reconnect during Python's final garbage collection.
                import gc
                gc.collect()
                application.backend.result_consumer.stop()
                application.close()
            shutdown()
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, subprocess.CalledProcessError) as exc:
        say('HATA: ' + str(exc))
        raise SystemExit(1) from exc
