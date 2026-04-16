# 🚀 API Subdomain Setup Guide

## Prerequisites
- ✅ Nginx installed on server
- ✅ SSL certificate for api.aegisnexus.dev (Let's Encrypt)
- ✅ API running on port 5000 (Uvicorn)

## Step 1: Copy Nginx Config

```bash
# Download from repo
git pull origin main

# Copy nginx config to available sites
sudo cp scripts/nginx-api-config.conf /etc/nginx/sites-available/api.aegisnexus.dev

# Create symlink to enable it
sudo ln -s /etc/nginx/sites-available/api.aegisnexus.dev /etc/nginx/sites-enabled/api.aegisnexus.dev
```

## Step 2: Edit Config (if needed)

```bash
sudo nano /etc/nginx/sites-available/api.aegisnexus.dev
```

Verify:
- `server_name api.aegisnexus.dev;` ✅
- SSL certificate paths exist ✅
- `proxy_pass http://localhost:5000;` ✅
- Frontend paths correct ✅

## Step 3: Test Nginx Config

```bash
sudo nginx -t
```

Output should be:
```
nginx: the configuration file /etc/nginx/nginx.conf syntax is ok
nginx: configuration will be successful
```

## Step 4: Reload Nginx

```bash
sudo systemctl reload nginx
```

Or restart if needed:
```bash
sudo systemctl restart nginx
```

## Step 5: Verify

```bash
# Check nginx is running
sudo systemctl status nginx

# Check API is reachable
curl -s https://api.aegisnexus.dev/api/v1/health | jq .

# You should see: {"status": "healthy", ...}
```

## Endpoints After Setup

- **Documentation:** https://api.aegisnexus.dev/docs
- **Test Panel:** https://api.aegisnexus.dev/test
- **API Endpoints:** https://api.aegisnexus.dev/api/v1/*
  - Health: https://api.aegisnexus.dev/api/v1/health
  - Check URL: https://api.aegisnexus.dev/api/v1/check-url?url=google.com
  - Stats: https://api.aegisnexus.dev/api/v1/stats

## SSL Certificate Renewal (Auto via Certbot)

If using Let's Encrypt with certbot:

```bash
sudo certbot renew --dry-run
```

Certbot auto-renews 30 days before expiry.

## Troubleshooting

**502 Bad Gateway**
- Check if API is running: `ps aux | grep uvicorn`
- Restart API if needed: `nohup uvicorn app.api_server:app --host 0.0.0.0 --port 5000 > logs/uvicorn.log 2>&1 &`

**SSL Certificate Error**
- Check cert exists: `ls /etc/letsencrypt/live/api.aegisnexus.dev/`
- Renew if needed: `sudo certbot renew --force-renewal`

**CORS Issues**
- API has CORS enabled, should work
- Check browser console for details
- Verify subdomain in API CORS settings if issues persist

**Cannot find frontend files**
- Verify paths in config match actual locations
- Check permissions: `sudo ls -la /var/www/aegis_nexus/frontend/`

## Monitoring

Check logs:
```bash
# Nginx access log
tail -f /var/log/nginx/api.aegisnexus.dev-access.log

# Nginx error log
tail -f /var/log/nginx/api.aegisnexus.dev-error.log

# API log
tail -f /var/www/aegis_nexus/logs/uvicorn.log
```

## Rollback

If something breaks:

```bash
# Disable site
sudo rm /etc/nginx/sites-enabled/api.aegisnexus.dev

# Reload nginx
sudo systemctl reload nginx

# Your main site will still work on port 80/443
```

---

**Questions?** Check nginx logs first:
```bash
sudo tail -30 /var/log/nginx/api.aegisnexus.dev-error.log
```
