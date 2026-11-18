"""The native launcher must isolate its broker without overwriting user settings."""
import importlib.util
from pathlib import Path


def runner(tmp_path, monkeypatch):
    source = Path(__file__).resolve().parents[1] / 'scripts/run_local.py'
    spec = importlib.util.spec_from_file_location('aegis_local_runner', source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module, 'ROOT', tmp_path)
    monkeypatch.setattr(module, 'STATE', tmp_path / 'data/local')
    monkeypatch.setattr(module, 'RUN', tmp_path / 'data/local/run')
    module.STATE.mkdir(parents=True)
    return module


def test_legacy_container_broker_cannot_break_native_start(tmp_path, monkeypatch):
    module = runner(tmp_path, monkeypatch)
    (tmp_path / '.env').write_text('CELERY_BROKER_URL=amqp://rabbitmq:5672//\nCELERY_RESULT_BACKEND=rpc://\n')
    env = module.environment()
    assert env['CELERY_BROKER_URL'].startswith('redis+socket:///')
    assert env['CELERY_RESULT_BACKEND'].endswith('?virtual_host=1')
    assert env['RUNTIME_DB_PATH'] == str(tmp_path / 'data/runtime.db')


def test_native_runner_preserves_explicit_database_and_browser(tmp_path, monkeypatch):
    module = runner(tmp_path, monkeypatch)
    monkeypatch.setenv('AEGIS_DATABASE_URL', 'sqlite:////private/tmp/owned.db')
    monkeypatch.setenv('AEGIS_CHROMIUM_PATH', '/custom/chromium')
    (module.STATE / 'chromium.path').write_text('/detected/chromium')
    env = module.environment()
    assert env['DATABASE_URL'] == 'sqlite:////private/tmp/owned.db'
    assert env['AEGIS_CHROMIUM_PATH'] == '/custom/chromium'


def test_stale_pid_file_does_not_authorize_killing_an_unrelated_process(tmp_path, monkeypatch, capsys):
    module = runner(tmp_path, monkeypatch)
    monkeypatch.chdir(tmp_path)
    module.RUN.mkdir()
    (module.RUN / 'launcher.json').write_text('{"pid":12345,"url":"http://localhost:8000"}')
    monkeypatch.setattr('sys.argv', ['run_local.py', 'stop'])
    monkeypatch.setattr(module.os, 'kill', lambda *args: (_ for _ in ()).throw(AssertionError('must not signal a stale PID')))
    assert module.main() == 0
    assert 'çalışmıyor' in capsys.readouterr().out


def test_new_launcher_clears_stale_pid_before_setup(tmp_path, monkeypatch):
    module = runner(tmp_path, monkeypatch)
    monkeypatch.chdir(tmp_path)
    module.RUN.mkdir()
    stale = module.RUN / 'launcher.json'
    stale.write_text('{"pid":12345,"url":"http://localhost:8000"}')
    monkeypatch.setattr('sys.argv', ['run_local.py', 'setup', '--no-install'])
    assert module.main() == 0
    assert not stale.exists()
