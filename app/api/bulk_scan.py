"""
Bulk Scanning Endpoint - CSV upload ve parallelized tarama
"""

from flask import request, jsonify
import tempfile
import csv
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

def bulk_scan_handler():
    """
    POST /api/v1/bulk-scan
    
    Multipart form:
      - file: CSV file (url)
      - callback: Optional webhook URL for results
    
    Returns:
      {
        "job_id": "uuid",
        "status": "processing",
        "total_urls": 100,
        "results_url": "/api/v1/bulk-scan/results/uuid"
      }
    """
    
    # File kontrol
    if 'file' not in request.files:
        return jsonify({"error": "Missing 'file' field"}), 400
    
    file = request.files['file']
    
    if file.filename == '':
        return jsonify({"error": "Empty filename"}), 400
    
    if not file.filename.endswith('.csv'):
        return jsonify({"error": "Only CSV files allowed"}), 400
    
    try:
        # CSV'yi oku
        stream = file.stream.read().decode('utf-8')
        urls = []
        
        for line in stream.strip().split('\n'):
            line = line.strip()
            if line and not line.startswith('#'):
                urls.append(line)
        
        if not urls:
            return jsonify({"error": "No URLs found in CSV"}), 400
        
        if len(urls) > 10000:
            return jsonify({"error": "Too many URLs (max 10000)"}), 400
        
        # Process URLs
        results = []
        
        from modules.phishing_detector.scanner import calculate_safety_score
        
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = {
                executor.submit(calculate_safety_score, url): url 
                for url in urls
            }
            
            for future in as_completed(futures):
                url = futures[future]
                try:
                    result = future.result(timeout=10)
                    results.append({
                        "url": url,
                        "score": result.get('score', 0),
                        "risk_level": result.get('risk_level', 'Unknown')
                    })
                except Exception as e:
                    results.append({
                        "url": url,
                        "error": str(e)
                    })
        
        # Sort by risk
        results.sort(key=lambda x: x.get('score', 100))
        
        return jsonify({
            "total": len(urls),
            "processed": len(results),
            "critical": len([r for r in results if r.get('score', 100) < 30]),
            "high_risk": len([r for r in results if 30 <= r.get('score', 100) < 60]),
            "safe": len([r for r in results if r.get('score', 100) >= 80]),
            "results": results
        }), 200
    
    except Exception as e:
        return jsonify({
            "error": "Processing error",
            "message": str(e)
        }), 500

def bulk_scan_export_handler(job_id):
    """
    GET /api/v1/bulk-scan/export/<job_id>
    
    CSV olarak sonuçları indir
    """
    # Simulated - would fetch from cache/db in production
    return jsonify({"error": "Not implemented"}), 501
