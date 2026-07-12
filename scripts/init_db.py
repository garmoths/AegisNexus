#!/usr/bin/env python3
"""
Database initialization script - Creates all required tables.

SETUP INSTRUCTIONS:
1. Run PostgreSQL setup as root/superuser FIRST:
   sudo psql -U postgres -f scripts/db_setup.sql

2. Then run this script:
   python scripts/init_db.py
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.database import engine
from app.models import Base


def init_database():
    """Create all tables defined in models."""
    print("🔄 Initializing database...")
    
    try:
        # Create all tables
        Base.metadata.create_all(bind=engine)
        print("✅ Database initialization complete!")
        print("\nCreated tables:")
        print("  - phishing_urls")
        print("  - whitelist_domains")
        print("  - honeypot_events")
        print("  - breach_records")
        print("  - password_checks")
        print("  - indicators_of_compromise")
        print("  - operator_api_keys")
        print("  - ioc_operator_alerts")
        return True
    
    except PermissionError as e:
        print(f"❌ Permission Denied!")
        print(f"Error: {e}")
        print("\nFIX: Run PostgreSQL setup as root first:")
        print("  sudo psql -U postgres -f scripts/db_setup.sql")
        return False
    
    except Exception as e:
        error_msg = str(e)
        if "permission denied" in error_msg.lower():
            print(f"❌ PostgreSQL Permission Error!")
            print(f"Error: {e}")
            print("\nFIX: Run PostgreSQL setup as root first:")
            print("  sudo psql -U postgres -f scripts/db_setup.sql")
            return False
        else:
            print(f"❌ Database initialization failed: {e}")
            return False


if __name__ == "__main__":
    success = init_database()
    sys.exit(0 if success else 1)

