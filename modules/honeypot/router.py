"""
02 - Honeypot Module Router (IP Avcısı)
Dolandırıcıları tersine mühendislik ile avlayan tuzak endpointleri
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session
from typing import Optional

from shared.utils.db import get_db
from app.models import HoneypotEvent
from .engine import honeypot_engine, HoneypotSession

router = APIRouter(tags=["02-honeypot"])


def _client_ip(request: Request) -> str:
    """İstemci IP adresini çıkar"""
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    if request.client:
        return request.client.host
    return "unknown"


class HoneypotInteractionRequest(BaseModel):
    session_id: str
    action: str  # login_attempt, otp_request, password_reset
    payload: Optional[dict] = None


class HoneypotCreateRequest(BaseModel):
    decoy_type: str = "bank_login"  # bank_login, social_login, shopping_login


# Gerçekçi banka login tuzak sayfası
_BANK_DECOY_HTML = """<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Ziraat Bankası - İnternet Şubesi</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #1a5f2a 0%, #0d3d1a 100%);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
        }
        .login-container {
            background: white;
            padding: 40px;
            border-radius: 8px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.3);
            width: 100%;
            max-width: 400px;
        }
        .logo {
            text-align: center;
            margin-bottom: 30px;
        }
        .logo h1 {
            color: #1a5f2a;
            font-size: 24px;
        }
        .form-group {
            margin-bottom: 20px;
        }
        label {
            display: block;
            margin-bottom: 5px;
            color: #333;
            font-weight: 500;
        }
        input {
            width: 100%;
            padding: 12px;
            border: 2px solid #ddd;
            border-radius: 4px;
            font-size: 14px;
            transition: border-color 0.3s;
        }
        input:focus {
            outline: none;
            border-color: #1a5f2a;
        }
        button {
            width: 100%;
            padding: 14px;
            background: #1a5f2a;
            color: white;
            border: none;
            border-radius: 4px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: background 0.3s;
        }
        button:hover {
            background: #124a1f;
        }
        .security-badge {
            text-align: center;
            margin-top: 20px;
            color: #666;
            font-size: 12px;
        }
        .hidden-warning {
            position: fixed;
            bottom: 10px;
            right: 10px;
            background: #ff4444;
            color: white;
            padding: 10px 20px;
            border-radius: 4px;
            font-size: 12px;
            opacity: 0.9;
        }
        #status-message {
            display: none;
            padding: 10px;
            margin-bottom: 15px;
            border-radius: 4px;
            text-align: center;
        }
        .error { background: #ffebee; color: #c62828; border: 1px solid #ef5350; }
        .info { background: #e3f2fd; color: #1565c0; border: 1px solid #42a5f5; }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="logo">
            <h1>Ziraat Bankası</h1>
            <p>İnternet Şubesi</p>
        </div>
        <div id="status-message"></div>
        <form id="login-form">
            <div class="form-group">
                <label>Müşteri/TCKN</label>
                <input type="text" id="customer-id" placeholder="Müşteri Numaranız veya TCKN" maxlength="11">
            </div>
            <div class="form-group">
                <label>Şifre</label>
                <input type="password" id="password" placeholder="Şifreniz">
            </div>
            <div class="form-group">
                <label>Onay Kodu</label>
                <input type="text" id="otp" placeholder="Telefonunuza gelen kod" maxlength="6">
            </div>
            <button type="submit" id="submit-btn">Giriş Yap</button>
        </form>
        <div class="security-badge">
            <p>128-bit SSL Güvenlik Sertifikası ile korunmaktadır</p>
        </div>
    </div>
    <div class="hidden-warning">
        ⚠️ BU SAYFA BİR TUZAKTIR - DOLANDIRICI AKTİF OLARAK İZLENİYOR
    </div>
    
    <script>
        // Session ID'yi URL'den al
        const urlParams = new URLSearchParams(window.location.search);
        const sessionId = urlParams.get('session') || 'unknown';
        
        let interactionCount = 0;
        let startTime = Date.now();
        
        // Sayfa yüklendiğinde oturum başlat
        fetch('/api/honeypot/session/ping', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({session_id: sessionId, action: 'page_load'})
        });
        
        document.getElementById('login-form').addEventListener('submit', async (e) => {
            e.preventDefault();
            interactionCount++;
            
            const customerId = document.getElementById('customer-id').value;
            const password = document.getElementById('password').value;
            const otp = document.getElementById('otp').value;
            
            const statusDiv = document.getElementById('status-message');
            statusDiv.style.display = 'block';
            statusDiv.className = 'info';
            statusDiv.textContent = 'Giriş yapılıyor...';
            document.getElementById('submit-btn').disabled = true;
            
            // Etkileşimi kaydet
            const response = await fetch('/api/honeypot/interaction', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({
                    session_id: sessionId,
                    action: 'login_attempt',
                    payload: {customer_id: customerId, has_otp: !!otp}
                })
            });
            
            const result = await response.json();
            
            setTimeout(() => {
                statusDiv.className = 'error';
                statusDiv.textContent = result.fake_error || 'Şifre hatalı. Tekrar deneyin.';
                document.getElementById('submit-btn').disabled = false;
                
                if (interactionCount >= 3) {
                    document.getElementById('otp').value = '';
                    document.getElementById('otp').placeholder = 'Yeni kod gönderildi (1:59)';
                }
            }, result.delay_seconds * 1000);
        });
        
        // Şifre sıfırlama linki (sahte)
        document.addEventListener('DOMContentLoaded', () => {
            const form = document.querySelector('.login-container');
            const resetLink = document.createElement('p');
            resetLink.innerHTML = '<a href="#" style="color: #1a5f2a; font-size: 14px;">Şifremi unuttum</a>';
            resetLink.style.textAlign = 'center';
            resetLink.style.marginTop = '15px';
            form.appendChild(resetLink);
            
            resetLink.querySelector('a').addEventListener('click', async (e) => {
                e.preventDefault();
                await fetch('/api/honeypot/interaction', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        session_id: sessionId,
                        action: 'password_reset'
                    })
                });
                alert('Şifre sıfırlama talimatları e-posta adresinize gönderildi.');
            });
        });
    </script>
</body>
</html>"""


@router.get("/decoy", response_class=HTMLResponse)
def honeypot_decoy_page(request: Request, db: Session = Depends(get_db)):
    """
    Gerçekçi banka login tuzak sayfası.
    Dolandırıcılar bu sayfayı görünce kandırıldıklarını sanacak.
    """
    ip = _client_ip(request)
    user_agent = request.headers.get("user-agent", "")
    
    # Yeni oturum oluştur
    session = honeypot_engine.create_session(ip, user_agent, "bank_login")
    
    # Veritabanına kaydet
    event = HoneypotEvent(
        client_ip=ip,
        user_agent=user_agent[:500],
        path="/api/v2/decoy",
        referer=request.headers.get("referer", "")[:500],
        note=f"session_id:{session.session_id}",
    )
    db.add(event)
    db.commit()
    
    # HTML'e session ID göm
    html_with_session = _BANK_DECOY_HTML.replace(
        "const sessionId = urlParams.get('session') || 'unknown';",
        f"const sessionId = '{session.session_id}';"
    )
    
    return HTMLResponse(content=html_with_session)


@router.post("/session/create")
def create_honeypot_session(
    req: HoneypotCreateRequest,
    request: Request,
    db: Session = Depends(get_db)
):
    """Yeni tuzak oturumu oluştur"""
    ip = _client_ip(request)
    user_agent = request.headers.get("user-agent", "")
    
    session = honeypot_engine.create_session(ip, user_agent, req.decoy_type)
    
    event = HoneypotEvent(
        client_ip=ip,
        user_agent=user_agent[:500],
        path="/api/v2/session/create",
        note=f"session_id:{session.session_id},decoy:{req.decoy_type}",
    )
    db.add(event)
    db.commit()
    
    return {
        "session_id": session.session_id,
        "decoy_page": f"/api/v2/decoy?session={session.session_id}",
        "decoy_type": req.decoy_type,
        "module": "02_honeypot"
    }


@router.post("/interaction")
def record_interaction(
    req: HoneypotInteractionRequest,
    request: Request,
    db: Session = Depends(get_db)
):
    """Dolandırıcı etkileşimini kaydet ve oyala"""
    result = honeypot_engine.process_interaction(req.session_id, req.action, req.payload)
    
    # Veritabanına kaydet
    ip = _client_ip(request)
    event = HoneypotEvent(
        client_ip=ip,
        user_agent=request.headers.get("user-agent", "")[:500],
        path=f"/api/v2/interaction",
        note=f"session_id:{req.session_id},action:{req.action},threat_score:{result.get('threat_score', 0)}",
    )
    db.add(event)
    db.commit()
    
    result["module"] = "02_honeypot"
    return result


@router.get("/stats")
def get_honeypot_stats(session_id: Optional[str] = None):
    """Honeypot istatistikleri - Kurtarılmış kurban sayısı"""
    stats = honeypot_engine.get_session_stats(session_id)
    stats["module"] = "02_honeypot"
    stats["social_impact"] = {
        "description": "Dolandırıcıların bu sayfada harcadığı her dakika, gerçek bir vatandaşın dolandırılmasını önler",
        "formula": "1 saat zaman kaybı = 12 potansiyel kurban kurtarıldı",
        "estimated_money_saved_tl": stats.get("estimated_money_saved_try", 0),
    }
    return stats


@router.post("/session/close")
def close_honeypot_session(session_id: str):
    """Oturumu kapat ve son raporu ver"""
    result = honeypot_engine.close_session(session_id)
    result["module"] = "02_honeypot"
    return result


@router.get("/decoy-types")
def get_decoy_types():
    """Mevcut tuzak türlerini listele"""
    return {
        "decoy_types": list(honeypot_engine.DECOY_TEMPLATES.keys()),
        "module": "02_honeypot",
        "description": "Her tuzak türü farklı dolandırıcı profiline hitap eder"
    }
