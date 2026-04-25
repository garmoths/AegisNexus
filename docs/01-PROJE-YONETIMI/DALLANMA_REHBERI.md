# 🌳 GIT BRANCHING STRATEGY - Ekip Çalışması

## 📋 QUICK START

### 1️⃣ Frontend Arkadaşı

```bash
# GitHub repo'dan clone et
git clone https://github.com/garmoths/AegisNexus.git
cd AegisNexus

# main branch'ten yeni branch oluştur
git checkout -b feature/frontend-development

# Çalış ve commit et
git add .
git commit -m "Add [feature name]"

# Push et
git push origin feature/frontend-development

# Pull request (PR) aç GitHub'da
# → Compare & pull request butonuna tıkla
# → main branch'e merge için review iste
```

### 2️⃣ Modules Arkadaşı

```bash
# Aynı şekilde
git clone https://github.com/garmoths/AegisNexus.git
cd AegisNexus

# modules branch oluştur
git checkout -b feature/modules-development

# Çalış, commit, push
git add .
git commit -m "Add/Update [module name]"
git push origin feature/modules-development

# PR aç → main branch'e merge iste
```

---

## 📊 BRANCHING STRUCTURE

```
main (production/stable)
├── feature/frontend-development (Arkadaş 1)
│   └── Çalışma: frontend/, web UI improvements
│
├── feature/modules-development (Arkadaş 2)
│   └── Çalışma: modules/, threat_intel, collectors
│
└── hotfix/... (emergency fixes)
```

---

## 🔄 WORKFLOW (Detailed)

### Step 1: Branch Oluştur

```bash
# Frontend için
git checkout main
git pull origin main  # Latest'i çek
git checkout -b feature/frontend-development

# Modules için
git checkout main
git pull origin main
git checkout -b feature/modules-development
```

### Step 2: Çalış ve Commit Et

```bash
# Dosya değiştir, test et
# Örnek: frontend/dashboard.html edit et

git status  # Hangi dosyalar değişti?
git add frontend/dashboard.html
git commit -m "Add real-time IOC dashboard widget"
```

### Step 3: Push Et

```bash
# Kendi branch'ine push et (main'e değil!)
git push origin feature/frontend-development
# veya
git push origin feature/modules-development
```

### Step 4: Pull Request (PR) Aç

1. GitHub'a git
2. Repo page'inde "Pull requests" tab'ı
3. "New pull request" butonuna tıkla
4. **Base branch:** main
5. **Compare branch:** feature/frontend-development (veya feature/modules-development)
6. Title & description yaz
7. "Create pull request" tıkla

### Step 5: Review & Merge

**Ben (repo owner) yapacağım:**
1. PR'ı review ederim
2. Conflict varsa söylerim
3. Approve edip merge yapacağım (GitHub'da)

---

## 🛑 CONFLICT RESOLUTION (Çakışma Çözme)

Eğer merge conflict olursa (çok nadiren):

```bash
# main branch'inde ne değişmiş görmek için
git fetch origin
git log origin/main --oneline -5

# Senin branch'inde çalış, sonra merge et
git merge origin/main

# Conflict var ise, dosya açıp manual düzelt
# Conflict marker'ları (<<<<<<, ======, >>>>>>) sil

# Düzelt, test et, commit et
git add .
git commit -m "Resolve merge conflicts"
git push origin feature/frontend-development
```

---

## ✅ BEST PRACTICES

### DO ✅
- Branch name'i descriptive yap: `feature/dashboard-redesign`
- Küçük, frequent commits yap (huge commits avoid)
- PR açmadan önce local'de test et
- PR description'a ne yaptığını yaz
- Latest main branch'i pull et before working

### DON'T ❌
- main branch'e directly push YAPMA
- Başkasının branch'ine push etme
- Huge commits (1000 line changes) yapma
- PR açmadan push-push-push yapma
- Merge conflicts'ı ignore etme

---

## 📝 COMMIT MESSAGE FORMAT

```
[Scope] Brief description

Longer description (optional)

Examples:
- [Frontend] Add IOC search widget
- [Modules] Fix URLhaus API timeout
- [Docs] Update deployment guide
```

---

## 🔍 GÜNLÜK COMMANDS

### Current branch'i görmek
```bash
git branch -a
```

### Latest changes görmek
```bash
git log --oneline -10
```

### Başkası'nın yaptığını görmek
```bash
git fetch origin
git log origin/feature/modules-development --oneline -5
```

### PR açmadan önce main'i pull et
```bash
git fetch origin
git merge origin/main
# Conflict yoksa tamam, yoksa çöz
```

---

## 🚨 EMERGENCY (Main broken ise)

```bash
# Neler yanlış gitti görmek
git log main --oneline -5
git diff main~1 main

# Revert et
git revert [commit_id]
git push origin main
```

---

## 📞 QUESTIONS?

Her zaman sor! İlk kez Git branch kullanıyorsan normal.

**Key Points:**
- `main` = production (şu anda Frankfurt'ta running)
- `feature/*` = safe place to experiment
- PR = code review mechanism
- Conflict = normal, easy to fix

---

**Status:** Ready for team collaboration ✅
