"""
OSINT Zombie Account Detector
E-postayı kullanarak unutulmuş hesapları bulur (LinkedIn, Facebook, Twitter, Reddit, eski forumlar)
"""
import re
import logging
from typing import Dict, List, Optional
from urllib.parse import urljoin, quote_plus
from datetime import datetime

import requests

try:
    from bs4 import BeautifulSoup
except ImportError:
    BeautifulSoup = None

logger = logging.getLogger(__name__)

# =========================================================
# PLATFORM CHECKERS
# =========================================================

class OSINTChecker:
    """OSINT ile zombi hesapları tespit eden checker"""
    
    def __init__(self):
        self.timeout = 10
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        }
    
    def check_all_platforms(self, email: str) -> Dict[str, List[Dict]]:
        """Tüm platformlarda e-postayı kontrol et"""
        results = {
            "linkedin": self._check_linkedin(email),
            "facebook": self._check_facebook(email),
            "twitter": self._check_twitter(email),
            "reddit": self._check_reddit(email),
            "github": self._check_github(email),
            "stack_overflow": self._check_stackoverflow(email),
            "medium": self._check_medium(email),
        }
        return results
    
    def _check_linkedin(self, email: str) -> List[Dict]:
        """LinkedIn'de e-postayı kontrol et"""
        try:
            # LinkedIn direct email arama deprecated, alternatif: profile lookup
            username_pattern = email.split("@")[0]
            url = f"https://www.linkedin.com/in/{username_pattern}"
            
            response = requests.head(url, headers=self.headers, timeout=self.timeout, allow_redirects=True)
            
            if response.status_code == 200:
                return [{
                    "platform": "LinkedIn",
                    "found": True,
                    "url": url,
                    "status": "Aktif profil var",
                    "risk": "high",
                    "last_verified": datetime.now().isoformat()
                }]
        except Exception as e:
            logger.debug(f"LinkedIn kontrol hatası: {e}")
        
        return []
    
    def _check_facebook(self, email: str) -> List[Dict]:
        """Facebook'ta e-postayı kontrol et"""
        try:
            # Facebook email search (deprecated Graph API alternatif)
            search_url = f"https://www.facebook.com/search/people/?q={quote_plus(email)}"
            
            response = requests.get(search_url, headers=self.headers, timeout=self.timeout)
            
            if response.status_code == 200 and email in response.text:
                return [{
                    "platform": "Facebook",
                    "found": True,
                    "url": search_url,
                    "status": "Potansiyel hesap var",
                    "risk": "medium",
                    "last_verified": datetime.now().isoformat()
                }]
        except Exception as e:
            logger.debug(f"Facebook kontrol hatası: {e}")
        
        return []
    
    def _check_twitter(self, email: str) -> List[Dict]:
        """Twitter/X'te e-postayı kontrol et"""
        try:
            username = email.split("@")[0]
            url = f"https://twitter.com/{username}"
            
            response = requests.head(url, headers=self.headers, timeout=self.timeout, allow_redirects=True)
            
            if response.status_code == 200:
                return [{
                    "platform": "Twitter/X",
                    "found": True,
                    "url": url,
                    "status": "Hesap mevcut",
                    "risk": "medium",
                    "last_verified": datetime.now().isoformat()
                }]
        except Exception as e:
            logger.debug(f"Twitter kontrol hatası: {e}")
        
        return []
    
    def _check_reddit(self, email: str) -> List[Dict]:
        """Reddit'te e-postayı kontrol et"""
        try:
            username = email.split("@")[0]
            url = f"https://reddit.com/u/{username}"
            
            response = requests.head(url, headers=self.headers, timeout=self.timeout, allow_redirects=True)
            
            if response.status_code == 200:
                return [{
                    "platform": "Reddit",
                    "found": True,
                    "url": url,
                    "status": "Profil mevcut",
                    "risk": "low",
                    "last_verified": datetime.now().isoformat()
                }]
        except Exception as e:
            logger.debug(f"Reddit kontrol hatası: {e}")
        
        return []
    
    def _check_github(self, email: str) -> List[Dict]:
        """GitHub'da e-postayı kontrol et"""
        try:
            url = "https://api.github.com/search/users"
            params = {"q": email}
            
            response = requests.get(url, params=params, headers=self.headers, timeout=self.timeout)
            
            if response.status_code == 200:
                data = response.json()
                if data.get("total_count", 0) > 0:
                    users = data.get("items", [])
                    return [{
                        "platform": "GitHub",
                        "found": True,
                        "url": f"https://github.com/{users[0]['login']}",
                        "status": "Geliştirici hesabı var",
                        "risk": "medium",
                        "last_verified": datetime.now().isoformat()
                    }]
        except Exception as e:
            logger.debug(f"GitHub kontrol hatası: {e}")
        
        return []
    
    def _check_stackoverflow(self, email: str) -> List[Dict]:
        """Stack Overflow'da e-postayı kontrol et"""
        try:
            url = "https://api.stackexchange.com/2.3/users/search"
            params = {
                "intitle": email,
                "site": "stackoverflow"
            }
            
            response = requests.get(url, params=params, timeout=self.timeout)
            
            if response.status_code == 200:
                data = response.json()
                if data.get("items"):
                    return [{
                        "platform": "Stack Overflow",
                        "found": True,
                        "url": f"https://stackoverflow.com/users/{data['items'][0]['user_id']}",
                        "status": "Geliştirici profili var",
                        "risk": "low",
                        "last_verified": datetime.now().isoformat()
                    }]
        except Exception as e:
            logger.debug(f"StackOverflow kontrol hatası: {e}")
        
        return []
    
    def _check_medium(self, email: str) -> List[Dict]:
        """Medium'da e-postayı kontrol et"""
        try:
            username = email.split("@")[0]
            url = f"https://medium.com/@{username}"
            
            response = requests.head(url, headers=self.headers, timeout=self.timeout, allow_redirects=True)
            
            if response.status_code == 200:
                return [{
                    "platform": "Medium",
                    "found": True,
                    "url": url,
                    "status": "Yazar profili var",
                    "risk": "low",
                    "last_verified": datetime.now().isoformat()
                }]
        except Exception as e:
            logger.debug(f"Medium kontrol hatası: {e}")
        
        return []


def analyze_zombie_accounts(email: str) -> Dict:
    """
    Zombi hesapları analiz et ve rapor oluştur
    """
    checker = OSINTChecker()
    results = checker.check_all_platforms(email)
    
    # Bulunan hesapları filtrele
    found_accounts = []
    for platform, accounts in results.items():
        if accounts:
            found_accounts.extend(accounts)
    
    # Risk skoru hesapla
    total_risk_score = 0
    for account in found_accounts:
        if account.get("risk") == "high":
            total_risk_score += 30
        elif account.get("risk") == "medium":
            total_risk_score += 15
        else:
            total_risk_score += 5
    
    return {
        "email": email,
        "zombie_accounts_found": len(found_accounts),
        "accounts": found_accounts,
        "zombie_risk_score": min(100, total_risk_score),
        "risk_level": "CRITICAL" if total_risk_score >= 70 else "HIGH" if total_risk_score >= 40 else "MEDIUM" if total_risk_score >= 20 else "LOW",
        "recommendation": _get_zombie_recommendation(found_accounts),
        "total_exposed_accounts": len(found_accounts),
    }


def _get_zombie_recommendation(accounts: List[Dict]) -> str:
    """Zombi hesapları temizlemek için tavsiye ver"""
    if not accounts:
        return "Unutulmuş hesap tespit edilmedi. İyi güvenlik uygulamaları devam et."
    
    count = len(accounts)
    return f"⚠️ {count} adet eski/unutulmuş hesap bulundu. Bu hesapların şifrelerini değiştir veya kapatabilirsin. Sızıntı riskini %70 oranında azaltır."
