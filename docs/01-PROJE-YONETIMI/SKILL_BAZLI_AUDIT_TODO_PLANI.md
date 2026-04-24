# AegisNexus Skill-Bazli Audit TODO Plani

Bu dokuman, `.continue/skills` altindaki aktif 8 skill temel alinarak hazirlanmis profesyonel audit ve temizlik TODO planidir.

## Kullanilan Skill Seti
- `systematic-debugging`
- `verification-before-completion`
- `api-security-testing`
- `ethical-hacking-methodology`
- `burp-suite-testing`
- `test-driven-development`
- `webapp-testing`
- `finishing-a-development-branch`

## Skill Eslestirmesi
- **Guvenlik sertlestirme:** `api-security-testing`, `ethical-hacking-methodology`, `burp-suite-testing`
- **Kok neden odakli bug giderme:** `systematic-debugging`
- **Regresyonu engelleyen gelistirme:** `test-driven-development`, `webapp-testing`
- **Teslim ve release disiplini:** `verification-before-completion`, `finishing-a-development-branch`

## Oncelikli TODO

### P0 - Kritik Guvenlik ve Erişim
- [ ] Secret kalintilarini temizle, exposed anahtarlari rotate et.
- [ ] Kritik endpointlerde auth/authz zorunlulugu uygula.
- [ ] Deploy entrypoint uyumsuzlugunu kaldir.
- [ ] API guvenlik test setini (broken auth, IDOR, injection, info leak) tamamla.

### P0 - Runtime Bozan Teknik Hatalar
- [ ] Model/route alan uyumsuzluklarini duzelt.
- [ ] Cache DB sema/kolon uyumsuzluklarini tekle.
- [ ] URL normalize kontratini tek veri modeline sabitle.
- [ ] Honeypot path uyumsuzluklarini frontend-backend contract ile hizala.

### P1 - Hijyen ve Kod Artigi Temizligi
- [ ] `.gitignore` standartlarini tamamla.
- [ ] Runtime artifactlarini repodan temizle (`venv`, `*.db`, `logs`, schedule, build tarball).
- [ ] Legacy/orphan dosyalari siniflandir (hemen sil / gecis sonrasi sil / koru).
- [ ] Duplicate endpoint ve mount edilmeyen router adaylarini testle karar ver.

### P1 - Kalite Kapilari
- [ ] Frontend lint kiriklarini release-blocking seviyede kapat.
- [ ] CI lint+test+security adimlarini ekle.
- [ ] TDD ile kritik backend pathlerine temel test seti ekle.
- [ ] Web smoke/regresyon testlerini Playwright ile devreye al.

### P1 - Mimari Sadelestirme
- [ ] FastAPI/Flask icin canonical backend kararini yazili hale getir.
- [ ] `frontend` ve `frontend-react` icin birincil UI kararini netlestir.
- [ ] API versiyonunu tek public contract altinda birlestir.

### P2 - Dokumantasyon ve Isletim Standarti
- [ ] Docs yapisinda active/archive ayrimini netlestir.
- [ ] README ve API dokumanlarini gercek calisma modeline hizala.
- [ ] Deploy, healthcheck, rollback ve verification runbook'unu tek kaynaga bagla.

## Karar Kurali: Silinsin mi, Kalsin mi?
- **Direkt silinebilir:** environment/runtime state dosyalari.
- **Testten sonra silinebilir:** route'a bagli olmayan veya duplicate kodlar.
- **Planli gecisle silinebilir:** legacy stack katmanlari.

## Definition of Done
- P0 maddeleri kapanmis ve dogrulanmis.
- CI kapilari yesil.
- Mimari karar ve dokuman uyumu saglanmis.
- Artifact/secret kaynakli riskler temizlenmis.
