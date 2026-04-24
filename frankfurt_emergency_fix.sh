#!/bin/bash

# Frankfurt Server Emergency Fix Script
# Fix phishing detector backend conflicts and restore data display

echo "🚨 Frankfurt Emergency Fix Starting..."

# 1. Check database connection
echo "📊 Checking database connection..."
cd /var/www/aegis_nexus/AegisNexus
source /var/www/aegisnexus/venv/bin/activate

python3 -c "
import sys
sys.path.append('.')
try:
    from shared.utils.db import SessionLocal
    from app.models import PhishingURL
    db = SessionLocal()
    count = db.query(PhishingURL).count()
    print(f'✅ Database connected! PhishingURL count: {count}')
    
    # Test latest entry
    latest = db.query(PhishingURL).order_by(PhishingURL.id.desc()).first()
    if latest:
        print(f'Latest entry: {latest.url[:50]}...')
        print(f'Created: {latest.created_at}')
    else:
        print('❌ No entries in PhishingURL table')
    
    db.close()
except Exception as e:
    print(f'❌ Database connection failed: {e}')
    print('Checking PostgreSQL status...')
    import subprocess
    result = subprocess.run(['systemctl', 'status', 'postgresql'], capture_output=True, text=True)
    print(result.stdout)
"

# 2. Test API endpoints
echo "🔍 Testing API endpoints..."
python3 -c "
import sys
sys.path.append('.')
try:
    import requests
    import json
    
    # Test latest endpoint
    print('Testing /api/v2/phishing/latest...')
    resp = requests.get('http://localhost:8000/api/v2/phishing/latest?limit=3', timeout=10)
    if resp.status_code == 200:
        data = resp.json()
        print(f'✅ Latest endpoint: {len(data.get(\"latest\", []))} entries')
        if data.get('latest'):
            print(f'First: {data[\"latest\"][0].get(\"domain\", \"N/A\")}')
    else:
        print(f'❌ Latest endpoint failed: {resp.status_code}')
    
    # Test history endpoint
    print('Testing /api/v2/phishing/history...')
    resp = requests.get('http://localhost:8000/api/v2/phishing/history?limit=3', timeout=10)
    if resp.status_code == 200:
        data = resp.json()
        print(f'✅ History endpoint: {len(data.get(\"history\", []))} entries')
    else:
        print(f'❌ History endpoint failed: {resp.status_code}')
        
except Exception as e:
    print(f'❌ API test failed: {e}')
"

# 3. Fix database connection if needed
echo "🔧 Fixing database connection..."
# Check if PostgreSQL is running
if ! systemctl is-active --quiet postgresql; then
    echo "Starting PostgreSQL..."
    sudo systemctl start postgresql
    sudo systemctl enable postgresql
fi

# 4. Restart services
echo "🔄 Restarting services..."
sudo systemctl restart aegis.service
sudo systemctl reload nginx

# 5. Verify fix
echo "✅ Verifying fix..."
sleep 5

python3 -c "
import sys
sys.path.append('.')
try:
    import requests
    
    # Final test
    resp = requests.get('http://localhost:8000/api/v2/phishing/latest?limit=1', timeout=10)
    if resp.status_code == 200:
        data = resp.json()
        if data.get('latest'):
            print('✅ Phishing detector FIXED!')
            print(f'Data showing: {len(data[\"latest\"])} entries')
        else:
            print('❌ Still no data')
    else:
        print(f'❌ Still broken: {resp.status_code}')
        
except Exception as e:
    print(f'❌ Verification failed: {e}')
"

echo "🎯 Emergency fix completed!"
echo "🌍 Check: https://modules.aegisnexus.dev"
echo "📊 API: http://localhost:8000/api/v2/phishing/latest"
