# 🔍 PULL REQUEST REVIEW PROCESS

## 📋 WORKFLOW (Arkadaşlar Push Yaptığında)

```
Arkadaş (feature/frontend veya feature/modules)
    ↓ Push yapıyor
    ↓
GitHub (PR açı kaldı)
    ↓ Sana notification geliyor
    ↓
Sen (main branch'i kontrol et, review, merge)
    ↓
Frankfurt Sunucusu (auto-deploy)
    ↓
PRODUCTION (live)
```

---

## ✅ SEN NE YAPACAKSIN?

### Step 1: PR Notification'ı Al

GitHub email/notification → "New pull request from feature/frontend-development"

### Step 2: PR'ı GitHub'da Aç

1. Repo'ya git: https://github.com/garmoths/AegisNexus
2. "Pull requests" tab'ına tıkla
3. Arkadaşın PR'ını aç

```
PR Title: [Frontend] Add real-time IOC dashboard
Base: main
Compare: feature/frontend-development

Files changed: 3
- frontend/dashboard.html (+50 lines)
- frontend/dashboard.js (+120 lines)
- frontend/styles.css (+30 lines)
```

### Step 3: Kodu Review Et

```
1. "Commits" tab'ında → commit message'leri oku
2. "Files changed" tab'ında → kodları satır satır oku
3. Sorun varsa → "Add a comment" / "Request changes"
4. Tamam ise → "Approve"
```

### Step 4: Merge Et

1. "Merge pull request" butonuna tıkla
2. Merge type seç:
   - "Create a merge commit" (default, recommended)
   - "Squash and merge" (commits'leri birleştir)
   - "Rebase and merge" (clean history)
3. "Confirm merge" tıkla

### Step 5: Branch Sil (Opsiyonel)

- PR merged olunca GitHub soracak: "Delete feature/frontend-development?"
- "Delete branch" tıkla (branch artık gereksiz)

---

## 📊 GITHUB PR DASHBOARD

GitHub'da PR'ları görmen için:
- https://github.com/garmoths/AegisNexus/pulls
- Açık (Open) PR'lar = İncelenmesi gerekenleri
- Closed PR'lar = Merged/rejected

---

## 🎯 REVIEW CHECKLIST

Arkadaşın PR'ında şunları kontrol et:

```
Code Quality:
☐ Kod temiz mi ve readable?
☐ Naming conventions uygun mu?
☐ Unnecessary comments var mı?
☐ Commented-out code var mı? (kaldır)

Functionality:
☐ Feature çalışıyor mu? (test ettiler mi?)
☐ Existing features'ı kırdılar mı?
☐ Edge cases handled mi?
☐ Error handling var mı?

Documentation:
☐ README updated mi?
☐ Inline comments açıklayıcı mı?
☐ API docs updated mi?

Testing:
☐ Unit tests var mı?
☐ Integration tests pass ediyor mu?
☐ Manual test sonucu ne?

Database:
☐ Schema changes var mı?
☐ Migrations written mi?
☐ Backwards compatible mi?

Security:
☐ SQL injection var mı?
☐ XSS vulnerabilities?
☐ Credentials/secrets committed mi? (KALDIR!)
☐ .env exposed mi?
```

---

## 💬 FEEDBACK VERMEK

### Request Changes (Kodu iade et)

```
Sorun bulursan:
1. Kod satırında hover → "Add single comment"
2. Sorun yazı → "Start a review"
3. "Request changes" seç

Arkadaş tekrar düzeltip push edecek
→ Otomatik PR update olacak
→ Tekrar review et
```

### Approve (Tamam, merge edebilir)

```
Sorun yoksa:
1. Review tab'ında
2. "Approve" butonuna tıkla
3. "Merge pull request" et
```

---

## 🚨 CONFLICT HANDLING

Eğer merge conflict varsa, GitHub gösterecek:

```
⚠️ "This branch has conflicts that must be resolved"
```

Conflict çözmek için:

**Option 1: GitHub Web Editor (simple conflicts)**
```
1. "Resolve conflicts" butonuna tıkla
2. GitHub açık editor'ı
3. Conflict markers'ları (<<<<<<, ======, >>>>>>) göreceksin
4. Hangisini tutmak istersen seç
5. "Mark as resolved"
6. Commit et
```

**Option 2: Local Komut (complex conflicts)**
```bash
# Arkadaşın branch'ini merge et
git fetch origin
git checkout feature/frontend-development
git merge origin/main

# Conflicts'ı düzelt
# VSCode'da red/green butonları var - orada seç

# Test et, commit et, push et
git add .
git commit -m "Resolve merge conflicts"
git push origin feature/frontend-development

# GitHub otomatik update olacak
```

---

## 📱 NOTIFICATION AYARLARI

GitHub ayarlarından:

Settings → Notifications
- Pull request reviews
- Pull request comments
- Enable email notifications

Böyle her PR'da bilgilendirileceksin.

---

## 🔄 AUTO-DEPLOY

Frankfurt sunucusu şu workflow'u kullanıyor:

```
main branch → GitHub Actions (CI/CD)
  ↓
Tests run
  ↓
Success? → Auto-deploy to Frankfurt
  ↓
Failure? → Notification, fix yapmalı
```

**IMPORTANT:** Merge ettikten sonra ~2 dakika sonra
Frankfurt sunucusu otomatik güncellenecek!

```
git pull origin main → yeni code inecek
requirements.txt → dependencies install
venv activate → env ready
services restart → API + cron active
```

---

## 📞 QUICK CHECKLIST

Arkadaş push yaptığında (şu sırayla):

1. ☐ Notification aldım
2. ☐ PR'ı GitHub'da açtım
3. ☐ Commits'leri inceledim
4. ☐ Files changed'i okudum
5. ☐ Kod review checklist geçti
6. ☐ Test etmelerini sordumsa (gerekirse)
7. ☐ Approve ettim
8. ☐ Merge pull request (GitHub web)
9. ☐ Branch sildim
10. ☐ Frankfurt'ta deployed mi? (1-2 dakika sonra)

---

## 🎯 ÖZET

**Senin role:**
- Git: Merge'leri handle et
- GitHub: PR'ları review et
- Quality: Code standards maintain et
- Production: Frankfurt'ta stable kalıyor

**Arkadaşlar'ın role:**
- Feature branch'lerinde çalış
- Sık commit + push
- PR aç
- Senin feedback'i bekle
- Güncellemeleri yap

---

**Status:** Ready for team PR workflow ✅
