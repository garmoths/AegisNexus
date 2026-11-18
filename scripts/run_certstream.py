"""Bağlı kurulum için uzun ömürlü CertStream dinleyicisi.

Yerel konsolda (``run.sh --crawler``) dinleyici zaten supervisor thread'i olarak
çalışır; bu script yalnızca Celery tabanlı bağlı kurulumda ayrı bir servis
(ör. systemd) olarak çalıştırmak içindir. Keşif açık ve etkin bir ``certstream``
kaynağı yokken boşta bekler; API anahtarı veya Redis gerektirmez.

Çalıştırma:
    .venv/bin/python scripts/run_certstream.py
Durdurma: Ctrl+C (SIGINT) veya SIGTERM.
"""
import signal
import threading
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.discovery.certstream import run  # noqa: E402


def main():
    stop = threading.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stop.set())
    print('AegisNexus CertStream dinleyicisi çalışıyor. Durdurmak için Ctrl+C.', flush=True)
    run(stop)
    print('Durduruldu.', flush=True)


if __name__ == '__main__':
    main()
