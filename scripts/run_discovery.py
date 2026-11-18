"""Start the self-contained AegisNexus crawler console on loopback."""
import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description='AegisNexus keşif konsolu: API anahtarı ve Redis gerekmez.')
    parser.add_argument('--port', type=int, default=8010)
    parser.add_argument('--no-build', action='store_true')
    args = parser.parse_args()
    if not 1024 <= args.port <= 65535:
        parser.error('Port 1024–65535 aralığında olmalı.')
    os.chdir(ROOT)
    env = {**os.environ, 'VITE_CRAWLER_MODE': 'true',
           'PYTHONPATH': str(ROOT), 'PYTHONUNBUFFERED': '1',
           'DATABASE_URL': os.getenv('AEGIS_DATABASE_URL') or 'sqlite:///' + str(ROOT / 'data/aegis.db')}
    # Keep the standalone runtime usable without installing Chromium until enabled.
    check = subprocess.run([sys.executable, '-c', 'import fastapi, sqlalchemy, bs4, requests, celery, dotenv'], capture_output=True)
    if check.returncode:
        subprocess.run([sys.executable, '-m', 'pip', 'install', '-r', str(ROOT / 'requirements.txt')], check=True)
    if not args.no_build:
        if not shutil.which('npm'):
            parser.error('Node.js 22.12+ ve npm gerekli.')
        front = ROOT / 'frontend-react'
        if not (front / 'node_modules').is_dir():
            subprocess.run(['npm', 'ci', '--no-fund', '--no-audit'], cwd=front, check=True)
        subprocess.run(['npm', 'run', 'build', '--', '--outDir', 'dist-crawler'], cwd=front, env=env, check=True)
    if not (ROOT / 'frontend-react/dist-crawler/index.html').exists():
        parser.error('Keşif arayüzü derlenmemiş; --no-build olmadan çalıştırın.')
    print(f'\nAegisNexus Keşif: http://127.0.0.1:{args.port}\nİlk kullanımda tarama kapalıdır. Adres ekleyip konsoldan başlatın.\nKapat: Ctrl+C\n', flush=True)
    os.execve(sys.executable, [sys.executable, '-m', 'uvicorn', 'app.discovery.server:app',
               '--host', '127.0.0.1', '--port', str(args.port), '--no-proxy-headers'], env)


if __name__ == '__main__':
    main()
