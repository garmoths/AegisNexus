#!/usr/bin/env python3
"""Test script to clean up empty phishing records"""
import sys
from pathlib import Path

# Add modules to path
sys.path.insert(0, str(Path(__file__).parent))

from modules.phishing_detector.cache_db import cleanup_empty_records

if __name__ == "__main__":
    print("Cleaning up empty phishing records...")
    deleted = cleanup_empty_records(days=30)
    print(f"Deleted {deleted} empty records")
