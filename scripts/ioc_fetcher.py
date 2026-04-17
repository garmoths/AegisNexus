#!/usr/bin/env python3
"""
🚨 IOC Fetcher - Automated Threat Intelligence Collector
Runs hourly on Frankfurt server to fetch and store IOCs
"""

import sys
import os
import logging
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from sqlalchemy.orm import Session
from sqlalchemy import text
from modules.honeypot.ioc_collector import IOCCollectorEngine
from app.database import SessionLocal
from app.models import IndicatorOfCompromise


# ============================================================================
# LOGGING SETUP
# ============================================================================

LOG_DIR = Path("/var/log/aegis")
LOG_DIR.mkdir(exist_ok=True, mode=0o755)

LOG_FILE = LOG_DIR / "ioc_collector.log"
ERROR_LOG = LOG_DIR / "ioc_collector_errors.log"

# Console logger
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger("ioc_fetcher")

# Error logger
error_handler = logging.FileHandler(ERROR_LOG)
error_handler.setLevel(logging.ERROR)
error_formatter = logging.Formatter(
    "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
error_handler.setFormatter(error_formatter)
logger.addHandler(error_handler)


# ============================================================================
# IOC FETCHER LOGIC
# ============================================================================

class IOCFetcher:
    """Automated IOC collection and storage."""
    
    def __init__(self):
        self.engine = IOCCollectorEngine()
        self.db = None
        self.stats = {
            "collected": 0,
            "persisted": 0,
            "errors": 0,
            "start_time": None,
            "end_time": None,
        }
    
    def connect_db(self):
        """Connect to PostgreSQL."""
        try:
            self.db = SessionLocal()
            # Test connection
            self.db.execute(text("SELECT 1"))
            logger.info("✅ Database connection successful")
            return True
        except Exception as e:
            logger.error(f"❌ Database connection failed: {e}")
            self.stats["errors"] += 1
            return False
    
    def fetch_iocs(self, sources=None):
        """Fetch IOCs from all configured sources."""
        if sources is None:
            # URLhaus and PhishTank timing out, use only AbuseIPDB for now
            sources = ["abuseipdb"]
        
        try:
            logger.info(f"🔄 Starting IOC collection from: {', '.join(sources)}")
            collected = self.engine.collect_all(include_sources=sources, limit=1000)
            self.stats["collected"] = len(collected)
            logger.info(f"✅ Collected {self.stats['collected']} IOCs")
            return collected
        except Exception as e:
            logger.error(f"❌ IOC collection error: {e}", exc_info=True)
            self.stats["errors"] += 1
            return []
    
    def persist_iocs(self, iocs):
        """Store IOCs in PostgreSQL."""
        if not iocs or not self.db:
            return 0
        
        persisted = 0
        skipped = 0
        
        for ioc in iocs:
            try:
                # Check if IOC already exists
                existing = self.db.query(IndicatorOfCompromise).filter(
                    IndicatorOfCompromise.ioc_value_hash == ioc.get_value_hash()
                ).first()
                
                if existing:
                    # Update existing
                    existing.detection_count += 1
                    existing.last_seen = datetime.now(timezone.utc)
                    skipped += 1
                else:
                    # Create new
                    db_ioc = IndicatorOfCompromise(
                        ioc_type=ioc.ioc_type,
                        ioc_value=ioc.ioc_value,
                        ioc_value_hash=ioc.get_value_hash(),
                        source=ioc.source,
                        threat_type=ioc.threat_type,
                        threat_tags=ioc.threat_tags or [],
                        risk_score=ioc.risk_score,
                        confidence=ioc.confidence,
                        first_seen=ioc.first_seen,
                        last_seen=ioc.last_seen,
                        detection_count=ioc.detection_count,
                        context=ioc.context,
                        ioc_metadata=ioc.ioc_metadata,
                        source_reference=ioc.source_reference,
                        status='active',
                    )
                    self.db.add(db_ioc)
                    persisted += 1
            
            except Exception as e:
                logger.error(f"❌ Error storing IOC {ioc.ioc_value}: {e}")
                self.stats["errors"] += 1
                continue
        
        try:
            self.db.commit()
            self.stats["persisted"] = persisted
            logger.info(f"✅ Persisted {persisted} new IOCs, {skipped} duplicates")
            return persisted
        except Exception as e:
            logger.error(f"❌ Database commit failed: {e}")
            self.db.rollback()
            self.stats["errors"] += 1
            return 0
    
    def get_stats(self):
        """Get IOC statistics from database."""
        try:
            if not self.db:
                return {}
            
            total = self.db.query(IndicatorOfCompromise).count()
            critical = self.db.query(IndicatorOfCompromise).filter(
                IndicatorOfCompromise.risk_score >= 95
            ).count()
            high_risk = self.db.query(IndicatorOfCompromise).filter(
                IndicatorOfCompromise.risk_score >= 80
            ).count()
            
            return {
                "total_iocs": total,
                "critical": critical,
                "high_risk": high_risk,
                "low_risk": total - high_risk,
            }
        except Exception as e:
            logger.error(f"❌ Stats query error: {e}")
            return {}
    
    def cleanup(self):
        """Close database connection."""
        try:
            if self.db:
                self.db.close()
                logger.info("✅ Database connection closed")
        except Exception as e:
            logger.error(f"⚠️  Cleanup error: {e}")
    
    def run(self):
        """Execute full IOC collection cycle."""
        self.stats["start_time"] = datetime.now(timezone.utc)
        
        try:
            # Connect to DB
            if not self.connect_db():
                raise Exception("Database connection failed")
            
            # Fetch IOCs
            iocs = self.fetch_iocs()
            
            # Persist to DB
            self.persist_iocs(iocs)
            
            # Get stats
            stats = self.get_stats()
            
            # Log completion
            self.stats["end_time"] = datetime.now(timezone.utc)
            duration = (self.stats["end_time"] - self.stats["start_time"]).total_seconds()
            
            logger.info("=" * 70)
            logger.info("🎯 IOC COLLECTION COMPLETE")
            logger.info("=" * 70)
            logger.info(f"Collected: {self.stats['collected']} IOCs")
            logger.info(f"Persisted: {self.stats['persisted']} new IOCs")
            logger.info(f"Errors: {self.stats['errors']}")
            logger.info(f"Duration: {duration:.2f}s")
            logger.info(f"Database Stats: {json.dumps(stats, indent=2)}")
            logger.info("=" * 70)
            
            return True
        
        except Exception as e:
            logger.error(f"❌ IOC FETCHER FAILED: {e}", exc_info=True)
            self.stats["errors"] += 1
            return False
        
        finally:
            self.cleanup()


# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

def main():
    """Main entry point."""
    logger.info("🚀 IOC Fetcher started")
    
    fetcher = IOCFetcher()
    success = fetcher.run()
    
    # Exit with appropriate code
    sys.exit(0 if success and fetcher.stats["errors"] == 0 else 1)


if __name__ == "__main__":
    main()
