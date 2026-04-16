"""
Phishing Scanner API v1
- /api/v1/check-url - URL güvenlik kontrolü
- /api/v1/whitelist - Whitelist yönetimi  
- /api/v1/stats - İstatistikler
- /api/v1/bulk-scan - Toplu tarama
"""

from flask import Blueprint, request, jsonify
from functools import wraps
import sys
import os
from datetime import datetime

# Path setup
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from modules.phishing_detector.scanner import calculate_safety_score, check_whitelist
import sqlite3

api_v1 = Blueprint('api_v1', __name__, url_prefix='/api/v1')

# ==================== RATE LIMITING ====================
from collections import defaultdict
from time import time

request_counts = defaultdict(list)
MAX_REQUESTS_PER_MINUTE = 60

def rate_limit(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        ip = request.remote_addr
        now = time()
        
        # Eski istekleri temizle
        request_counts[ip] = [t for t in request_counts[ip] if now - t < 60]
        
        if len(request_counts[ip]) >= MAX_REQUESTS_PER_MINUTE:
            return jsonify({
                "error": "Rate limit exceeded",
                "message": f"Maximum {MAX_REQUESTS_PER_MINUTE} requests per minute"
            }), 429
        
        request_counts[ip].append(now)
        return f(*args, **kwargs)
    return decorated_function

# ==================== ENDPOINTS ====================

@api_v1.route('/check-url', methods=['GET'])
@rate_limit
def check_url():
    """
    URL güvenlik kontrolü
    
    Query params:
      - url: Kontrol edilecek URL (required)
      - detailed: Detaylı çıktı (true/false, default: false)
    
    Response:
      {
        "url": "https://example.com",
        "score": 95,
        "risk_level": "✅ Güvenli",
        "details": [...],
        "sources": [...],
        "timestamp": "2026-04-16T13:36:31Z"
      }
    """
    url = request.args.get('url')
    detailed = request.args.get('detailed', 'false').lower() == 'true'
    
    if not url:
        return jsonify({"error": "Missing 'url' parameter"}), 400
    
    if not url.startswith(('http://', 'https://')):
        url = f"https://{url}"
    
    try:
        result = calculate_safety_score(url)
        
        response = {
            "url": url,
            "score": result.get('score', 0),
            "risk_level": result.get('risk_level', 'Unknown'),
            "timestamp": datetime.utcnow().isoformat() + 'Z'
        }
        
        if detailed:
            response["details"] = result.get('details', [])
            response["sources"] = result.get('sources', [])
        
        return jsonify(response), 200
    
    except Exception as e:
        return jsonify({
            "error": "Scanning error",
            "message": str(e)
        }), 500

@api_v1.route('/whitelist', methods=['GET'])
@rate_limit
def get_whitelist():
    """
    Whitelist'teki tüm domain'leri getir
    
    Query params:
      - category: Filtre (optional)
      - limit: Kaç tane getir (default: 100)
    
    Response:
      {
        "total": 232,
        "domains": [
          {"domain": "google.com", "category": "Tech", "verified": true},
          ...
        ]
      }
    """
    category = request.args.get('category')
    limit = int(request.args.get('limit', 100))
    
    try:
        db_path = '/var/www/aegis_nexus/data/whitelist.db'
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Total count
        cursor.execute("SELECT COUNT(*) as count FROM whitelist_domains")
        total = cursor.fetchone()['count']
        
        # Fetch domains
        if category:
            cursor.execute("""
                SELECT domain, category, trusted_level, verified, company_name
                FROM whitelist_domains 
                WHERE category = ? 
                LIMIT ?
            """, (category, limit))
        else:
            cursor.execute("""
                SELECT domain, category, trusted_level, verified, company_name
                FROM whitelist_domains 
                LIMIT ?
            """, (limit,))
        
        domains = [dict(row) for row in cursor.fetchall()]
        conn.close()
        
        return jsonify({
            "total": total,
            "returned": len(domains),
            "domains": domains
        }), 200
    
    except Exception as e:
        return jsonify({
            "error": "Database error",
            "message": str(e)
        }), 500

@api_v1.route('/whitelist/add', methods=['POST'])
@rate_limit
def add_whitelist():
    """
    Whitelist'e domain ekle
    
    JSON body:
      {
        "domain": "example.com",
        "category": "Custom",
        "company_name": "Example Inc",
        "trusted_level": "high"
      }
    
    Response:
      {"success": true, "message": "Domain added", "domain": "example.com"}
    """
    data = request.get_json()
    
    if not data or 'domain' not in data:
        return jsonify({"error": "Missing 'domain' in request"}), 400
    
    domain = data['domain'].lower().strip()
    category = data.get('category', 'Custom')
    company_name = data.get('company_name', domain.split('.')[0].title())
    trusted_level = data.get('trusted_level', 'high')
    
    try:
        db_path = '/var/www/aegis_nexus/data/whitelist.db'
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT OR IGNORE INTO whitelist_domains 
            (domain, domain_norm, category, company_name, trusted_level, verified)
            VALUES (?, ?, ?, ?, ?, 1)
        """, (domain, domain, category, company_name, trusted_level))
        
        conn.commit()
        conn.close()
        
        return jsonify({
            "success": True,
            "message": "Domain added to whitelist",
            "domain": domain
        }), 201
    
    except Exception as e:
        return jsonify({
            "error": "Database error",
            "message": str(e)
        }), 500

@api_v1.route('/whitelist/remove', methods=['POST'])
@rate_limit
def remove_whitelist():
    """
    Whitelist'ten domain çıkar
    
    JSON body: {"domain": "example.com"}
    """
    data = request.get_json()
    
    if not data or 'domain' not in data:
        return jsonify({"error": "Missing 'domain' in request"}), 400
    
    domain = data['domain'].lower().strip()
    
    try:
        db_path = '/var/www/aegis_nexus/data/whitelist.db'
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        cursor.execute("DELETE FROM whitelist_domains WHERE domain_norm = ?", (domain,))
        conn.commit()
        deleted = cursor.rowcount
        conn.close()
        
        return jsonify({
            "success": True,
            "message": f"Deleted {deleted} domain(s)",
            "domain": domain
        }), 200
    
    except Exception as e:
        return jsonify({
            "error": "Database error",
            "message": str(e)
        }), 500

@api_v1.route('/stats', methods=['GET'])
@rate_limit
def get_stats():
    """
    Tarama istatistikleri
    
    Response:
      {
        "phishing_urls": 156,
        "whitelist_domains": 232,
        "last_fetch": "2026-04-16T02:00:00Z",
        "categories": {...}
      }
    """
    try:
        db_path = '/var/www/aegis_nexus/data/whitelist.db'
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Whitelist stats
        cursor.execute("SELECT COUNT(*) as count FROM whitelist_domains")
        whitelist_count = cursor.fetchone()[0]
        
        cursor.execute("""
            SELECT category, COUNT(*) as count 
            FROM whitelist_domains 
            GROUP BY category
        """)
        categories = {row[0]: row[1] for row in cursor.fetchall()}
        
        conn.close()
        
        return jsonify({
            "whitelist_domains": whitelist_count,
            "categories": categories,
            "last_update": datetime.utcnow().isoformat() + 'Z'
        }), 200
    
    except Exception as e:
        return jsonify({
            "error": "Database error",
            "message": str(e)
        }), 500

@api_v1.route('/health', methods=['GET'])
def health():
    """
    API health check
    """
    return jsonify({
        "status": "healthy",
        "version": "1.0",
        "timestamp": datetime.utcnow().isoformat() + 'Z'
    }), 200
