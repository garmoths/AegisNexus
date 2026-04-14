"""
Dark Web & Public Paste Site Scanner for breach data discovery.
Scans Pastebin, GitHub Gist, Paste.org for leaked email addresses.
"""

import requests
import re
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime
from urllib.parse import quote
import time

logger = logging.getLogger(__name__)

class DarkWebScanner:
    """Scans public paste sites and dark web accessible sources for breaches."""
    
    # Public paste site APIs and endpoints
    PASTE_SOURCES = {
        "pastebin": {
            "url": "https://pastebin.com/api/v1/as/getp",
            "search_url": "https://pastebin.com/search",
            "ratelimit": 1,  # seconds between requests
        },
        "github_gist": {
            "url": "https://api.github.com/search/gists",
            "search_url": "https://api.github.com/search/gists",
            "ratelimit": 1,
        },
        "paste_org": {
            "url": "https://paste.org",
            "search_url": "https://paste.org/search",
            "ratelimit": 2,
        }
    }
    
    # Email pattern for detection
    EMAIL_PATTERN = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
    
    # Credential pattern (common formats in breaches)
    CREDENTIAL_PATTERN = re.compile(
        r'(?:email|mail|user|username)[:\s=]+([^,\n]+)'
        r'.*?(?:password|pass|pwd|key)[:\s=]+([^,\n]+)',
        re.IGNORECASE | re.DOTALL
    )
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
        })
        self.last_request_time = {}
    
    def scan_for_email(self, email: str) -> Dict[str, Any]:
        """
        Scan dark web and paste sites for email address.
        
        Args:
            email: Email address to search for
            
        Returns:
            Dictionary with findings
        """
        findings = {
            "email": email,
            "found_in_pastes": [],
            "found_in_forums": [],
            "risk_assessment": "LOW",
            "total_occurrences": 0,
            "scan_timestamp": datetime.utcnow().isoformat()
        }
        
        # Search GitHub Gist (public, fast)
        gist_results = self._search_github_gist(email)
        if gist_results:
            findings["found_in_pastes"].extend(gist_results)
        
        # Search Pastebin (requires manual parsing due to API limits)
        pastebin_results = self._search_pastebin_public(email)
        if pastebin_results:
            findings["found_in_pastes"].extend(pastebin_results)
        
        # Search paste.org
        paste_org_results = self._search_paste_org(email)
        if paste_org_results:
            findings["found_in_pastes"].extend(paste_org_results)
        
        # Risk assessment
        findings["total_occurrences"] = len(findings["found_in_pastes"]) + len(findings["found_in_forums"])
        findings["risk_assessment"] = self._assess_risk(findings["found_in_pastes"])
        
        return findings
    
    def _search_github_gist(self, email: str) -> List[Dict[str, Any]]:
        """Search GitHub Gist for email address."""
        try:
            self._rate_limit("github_gist")
            
            # Search for email in gists (requires authentication for higher limits, but public search works)
            response = self.session.get(
                "https://api.github.com/search/gists",
                params={"q": email, "sort": "updated", "order": "desc"},
                timeout=10
            )
            
            if response.status_code != 200:
                return []
            
            results = []
            data = response.json()
            
            for gist in data.get("items", [])[:5]:  # Top 5 results
                gist_detail = {
                    "source": "GitHub Gist",
                    "title": gist.get("description", "No title"),
                    "url": gist.get("html_url"),
                    "created": gist.get("created_at"),
                    "updated": gist.get("updated_at"),
                    "preview": gist.get("id")[:50],
                    "risk_score": 0.6,
                    "reason": "Email found in public code/data gist"
                }
                results.append(gist_detail)
                logger.info(f"GitHub Gist finding: {gist['html_url']}")
            
            return results
        
        except Exception as e:
            logger.error(f"GitHub Gist search failed: {e}")
            return []
    
    def _search_pastebin_public(self, email: str) -> List[Dict[str, Any]]:
        """Search Pastebin scraping (limited by robots.txt - use with caution)."""
        try:
            self._rate_limit("pastebin")
            
            # Note: Pastebin's search is heavily restricted. This is a best-effort approach.
            # For production, use official Pastebin API with proper credentials
            search_url = f"https://pastebin.com/search?q={quote(email)}"
            
            response = self.session.get(search_url, timeout=10)
            
            if response.status_code != 200:
                return []
            
            # Simple regex-based extraction of paste IDs (limited reliability)
            paste_ids = re.findall(r'/([a-zA-Z0-9]{8})', response.text)
            
            results = []
            for paste_id in paste_ids[:3]:  # Limit to 3 results
                results.append({
                    "source": "Pastebin",
                    "url": f"https://pastebin.com/{paste_id}",
                    "paste_id": paste_id,
                    "preview": paste_id,
                    "risk_score": 0.7,
                    "reason": "Email potentially in paste content",
                    "note": "Requires verification - HTML parsing limited"
                })
            
            return results
        
        except Exception as e:
            logger.warning(f"Pastebin search limited: {e}")
            return []
    
    def _search_paste_org(self, email: str) -> List[Dict[str, Any]]:
        """Search paste.org for email address."""
        try:
            self._rate_limit("paste_org")
            
            response = self.session.get(
                "https://paste.org/search",
                params={"q": email},
                timeout=10
            )
            
            if response.status_code != 200:
                return []
            
            # Extract paste links from HTML
            paste_links = re.findall(r'href="(/paste/[^"]+)"', response.text)
            
            results = []
            for link in paste_links[:3]:
                results.append({
                    "source": "paste.org",
                    "url": f"https://paste.org{link}",
                    "preview": link,
                    "risk_score": 0.6,
                    "reason": "Email found in paste"
                })
            
            return results
        
        except Exception as e:
            logger.warning(f"Paste.org search failed: {e}")
            return []
    
    def _rate_limit(self, source: str):
        """Simple rate limiting to avoid being blocked."""
        if source in self.last_request_time:
            elapsed = time.time() - self.last_request_time[source]
            wait_time = self.PASTE_SOURCES[source]["ratelimit"] - elapsed
            if wait_time > 0:
                time.sleep(wait_time)
        
        self.last_request_time[source] = time.time()
    
    def _assess_risk(self, findings: List[Dict]) -> str:
        """Assess risk based on number and type of findings."""
        if not findings:
            return "LOW"
        
        total_risk = sum(f.get("risk_score", 0.5) for f in findings)
        avg_risk = total_risk / len(findings)
        
        if avg_risk >= 0.8:
            return "CRITICAL"
        elif avg_risk >= 0.6:
            return "HIGH"
        elif avg_risk >= 0.4:
            return "MEDIUM"
        else:
            return "LOW"
    
    def analyze_paste_content(self, paste_url: str) -> Dict[str, Any]:
        """
        Fetch and analyze paste content for credentials/data types.
        
        Args:
            paste_url: URL of the paste
            
        Returns:
            Analysis of paste content
        """
        try:
            response = self.session.get(paste_url, timeout=10)
            if response.status_code != 200:
                return {"error": "Could not fetch paste"}
            
            content = response.text[:5000]  # Limit to first 5KB
            
            # Count occurrences of common data types
            email_count = len(self.EMAIL_PATTERN.findall(content))
            credential_matches = self.CREDENTIAL_PATTERN.findall(content)
            
            # Detect data types present
            data_types = []
            if email_count > 0:
                data_types.append(f"Emails ({email_count})")
            if re.search(r'\b\d{16}\b', content):  # Credit card-like
                data_types.append("Possible credit card numbers")
            if re.search(r'\b\d{9}\b', content):  # SSN-like
                data_types.append("Possible SSN/ID numbers")
            if credential_matches:
                data_types.append(f"Username/password pairs ({len(credential_matches)})")
            
            return {
                "url": paste_url,
                "data_types_found": data_types,
                "email_occurrences": email_count,
                "credential_pairs": len(credential_matches),
                "content_size": len(content),
                "risk_level": "CRITICAL" if len(data_types) > 2 else "HIGH" if data_types else "LOW"
            }
        
        except Exception as e:
            logger.error(f"Paste analysis failed: {e}")
            return {"error": str(e), "url": paste_url}


def get_dark_web_scanner() -> DarkWebScanner:
    """Factory function to get scanner instance."""
    return DarkWebScanner()
