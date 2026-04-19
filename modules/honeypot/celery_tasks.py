from celery import Celery
import os
from dotenv import load_dotenv

load_dotenv()

app = Celery('honeypot', broker='amqp://guest:guest@localhost:5672//')

@app.task(bind=True, max_retries=3)
def fetch_urlhaus(self):
    try:
        from .ioc_collector import AbuseChCollector
        collector = AbuseChCollector()
        result = collector.fetch_urlhaus_recent()
        return {"status": "success", "count": len(result)}
    except Exception as e:
        self.retry(exc=e, countdown=60)

@app.task(bind=True, max_retries=3)
def fetch_phishtank(self):
    try:
        from .ioc_collector import AbuseChCollector
        collector = AbuseChCollector()
        result = collector.fetch_phishtank_recent()
        return {"status": "success", "count": len(result)}
    except Exception as e:
        self.retry(exc=e, countdown=60)

@app.task(bind=True, max_retries=3)
def fetch_otx(self):
    try:
        from .ioc_collector import AlienVaultOTXCollector
        collector = AlienVaultOTXCollector()
        result = collector.fetch_recent_pulses()
        return {"status": "success", "count": len(result)}
    except Exception as e:
        self.retry(exc=e, countdown=60)

@app.task
def run_ioc_fetch():
    """Tüm IOC tasks'ı parallel çalıştır"""
    fetch_urlhaus.delay()
    fetch_phishtank.delay()
    fetch_otx.delay()
