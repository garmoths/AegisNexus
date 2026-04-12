"""Demonstrasyon: yalnızca bu uygulamaya gelen istekler kaydedilir."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from app.deps import get_db
from app.models import HoneypotEvent

router = APIRouter(tags=["honeypot"])


def _client_ip(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    if request.client:
        return request.client.host
    return "unknown"


_DECOY_HTML = """<!DOCTYPE html>
<html lang="tr">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Demo — Güvenlik Tuzak Sayfası</title>
  <style>
    body { font-family: system-ui, sans-serif; background:#111; color:#eee; max-width:480px; margin:2rem auto; padding:1rem; }
    .warn { background:#422; border:1px solid #f66; padding:12px; margin-bottom:16px; font-size:14px; }
    input { width:100%; padding:10px; margin:8px 0; box-sizing:border-box; background:#222; border:1px solid #555; color:#fff; }
    button { width:100%; padding:12px; background:#333; color:#0f0; border:1px solid #0f0; cursor:pointer; margin-top:8px; }
  </style>
</head>
<body>
  <div class="warn">
    <strong>Bu sayfa sahtedir.</strong> Aegis Nexus adlı eğitim/demonstrasyon ortamının bir parçasıdır.
    Gerçek kullanıcı adı veya şifre yazmayın; alanlar kasıyla kilitlidir. Sayfa açıldığında tarayıcınız,
    yalnızca bu uygulamanın sunucusuna anonim bir “ziyaret” sinyali gönderir (ör. IP ve tarayıcı bilgisi).
    Bu mekanizmayı yasalara aykırı veya başkalarını aldatmak için kullanmayın.
  </div>
  <h1>Oturum doğrulama (gösterim amaçlı)</h1>
  <p>Aşağıdaki form gerçek değildir; oltalama sayfalarının nasıl göründüğünü anlatmak için tasarlanmıştır.</p>
  <input type="text" placeholder="Kullanıcı adı" disabled>
  <input type="password" placeholder="Şifre" disabled>
  <button type="button" disabled>Giriş</button>
  <script>
    fetch('/api/honeypot/ping', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' })
      .catch(function(){});
  </script>
</body>
</html>"""


@router.get("/honeypot/decoy", response_class=HTMLResponse)
def honeypot_decoy():
    return HTMLResponse(_DECOY_HTML)


@router.post("/api/honeypot/ping")
def honeypot_ping(request: Request, db: Session = Depends(get_db)):
    ev = HoneypotEvent(
        client_ip=_client_ip(request),
        user_agent=(request.headers.get("user-agent") or "")[:500],
        path="/honeypot/decoy",
        referer=(request.headers.get("referer") or "")[:500],
        note="decoy_ping",
    )
    db.add(ev)
    db.commit()
    return {
        "durum": "kaydedildi",
        "mesaj": "Bu istek yalnızca yerel veritabanına teknik ziyaret kaydı olarak yazıldı.",
    }


@router.get("/api/honeypot/stats")
def honeypot_stats(db: Session = Depends(get_db)):
    n = db.query(HoneypotEvent).count()
    return {
        "honeypot_visits_recorded": n,
        "aciklama": "Tuzak sayfasının açılması veya ping uç noktasının çağrılması ile artan toplam kayıt sayısı.",
    }
