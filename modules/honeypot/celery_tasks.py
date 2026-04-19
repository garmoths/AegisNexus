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
        result = collector.fetch_urlhaus_recent(limit=500)
        return {"status": "success", "count": len(result)}
    except Exception as e:
        self.retry(exc=e, countdown=60)

@app.task(bind=True, max_retries=3)
def fetch_otx(self):
    try:
        from .ioc_collector import AlienVaultOTXCollector
        collector = AlienVaultOTXCollector()
        result = collector.fetch_recent_pulses(limit=100)
        return {"status": "success", "count": len(result)}
    except Exception as e:
        self.retry(exc=e, countdown=60)

@app.task
def run_ioc_fetch():
    """Parallel IOC fetcher"""
    fetch_urlhaus.delay()
    fetch_otx.delay()
