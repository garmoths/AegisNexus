"""
Flask API Server - Phishing Scanner API
Standalone API server that runs alongside FastAPI
"""

from flask import Flask, jsonify
from flask_cors import CORS
import os
import sys

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.api.routes import api_v1

def create_app():
    """Create and configure Flask app"""
    app = Flask(__name__)
    
    # Configuration
    app.config['JSON_SORT_KEYS'] = False
    app.config['JSONIFY_PRETTYPRINT_REGULAR'] = True
    
    # Enable CORS for all routes
    CORS(app, resources={r"/api/*": {"origins": "*"}})
    
    # Register blueprints
    app.register_blueprint(api_v1)
    
    # Root endpoint
    @app.route('/', methods=['GET'])
    def root():
        return jsonify({
            "name": "Aegis Nexus Phishing Scanner API",
            "version": "1.0",
            "endpoints": {
                "check-url": "/api/v1/check-url?url=https://example.com",
                "whitelist": "/api/v1/whitelist",
                "whitelist-add": "POST /api/v1/whitelist/add",
                "whitelist-remove": "POST /api/v1/whitelist/remove",
                "stats": "/api/v1/stats",
                "health": "/api/v1/health"
            }
        }), 200
    
    # Error handlers
    @app.errorhandler(404)
    def not_found(e):
        return jsonify({"error": "Not found", "message": str(e)}), 404
    
    @app.errorhandler(500)
    def server_error(e):
        return jsonify({"error": "Server error", "message": str(e)}), 500
    
    return app

if __name__ == '__main__':
    app = create_app()
    port = int(os.getenv('API_PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
