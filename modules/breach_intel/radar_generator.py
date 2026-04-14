"""
Veri Radarı Görselleştirmesi
E-posta merkezli, sızıntılardan gelen oklar gösteren D3.js uyumlu veri yapısı
"""
import logging
from typing import Dict, List, Optional
from datetime import datetime
import hashlib

logger = logging.getLogger(__name__)


class RadarGenerator:
    """Veri radarı görselleştirmesi oluşturur"""
    
    def __init__(self):
        self.color_map = {
            "CRITICAL": "#FF0000",      # Kırmızı
            "HIGH": "#FF6B00",          # Turuncu-kırmızı
            "MEDIUM": "#FFA500",        # Turuncu
            "LOW": "#FFD700",           # Altın
            "INFO": "#00BFFF",          # Mavi
        }
    
    def generate_radar_data(
        self,
        email: str,
        breaches: List[Dict],
        zombie_accounts: Optional[List[Dict]] = None,
        threat_profile: Optional[Dict] = None
    ) -> Dict:
        """
        Radar için D3.js uyumlu JSON veri yapısı oluştur
        
        Yapı:
        - Center node: E-posta
        - Breach nodes: Sızıntılar
        - Links: E-posta'dan sızıntılara oklar
        - Severity colors: Tehlike seviyesine göre renkler
        """
        
        # Center node (e-posta)
        email_hash = hashlib.md5(email.encode()).hexdigest()
        center_node = {
            "id": f"email_{email_hash[:8]}",
            "label": email,
            "type": "email",
            "size": 50,
            "color": "#1E90FF",  # Mavi
            "fill": "solid"
        }
        
        # Breach nodes ve links
        nodes = [center_node]
        links = []
        
        for idx, breach in enumerate(breaches):
            breach_id = f"breach_{idx}_{hashlib.md5(breach.get('name', '').encode()).hexdigest()[:8]}"
            
            # Breach'ün risk seviyesini belirle
            risk_level = self._get_breach_risk_level(breach)
            
            # Breach node'u
            node = {
                "id": breach_id,
                "label": breach.get("name", "Unknown Breach"),
                "type": "breach",
                "size": 30,
                "color": self.color_map.get(risk_level, "#FFD700"),
                "fill": "solid",
                "breach_date": breach.get("breach_date", "Unknown"),
                "data_classes": breach.get("data_classes", []),
                "records_exposed": self._estimate_records(breach.get("name", "")),
                "risk_level": risk_level
            }
            nodes.append(node)
            
            # Link (e-posta'dan breach'e)
            link = {
                "source": center_node["id"],
                "target": breach_id,
                "strength": 0.7,
                "distance": 100,
                "color": self.color_map.get(risk_level, "#FFD700"),
                "opacity": 0.6,
                "width": self._get_link_width(risk_level)
            }
            links.append(link)
        
        # Zombi hesaplar (isteğe bağlı)
        if zombie_accounts:
            for idx, zombie in enumerate(zombie_accounts):
                zombie_id = f"zombie_{idx}_{hashlib.md5(zombie.get('platform', '').encode()).hexdigest()[:8]}"
                
                zombie_node = {
                    "id": zombie_id,
                    "label": f"{zombie.get('platform', 'Unknown')} (Zombi)",
                    "type": "zombie",
                    "size": 25,
                    "color": "#9932CC",  # Mor
                    "fill": "striped",
                    "platform": zombie.get("platform", ""),
                    "status": zombie.get("status", "Unknown"),
                    "risk": zombie.get("risk", "medium")
                }
                nodes.append(zombie_node)
                
                zombie_link = {
                    "source": center_node["id"],
                    "target": zombie_id,
                    "strength": 0.5,
                    "distance": 80,
                    "color": "#9932CC",
                    "opacity": 0.4,
                    "width": 2
                }
                links.append(zombie_link)
        
        # Threat profile (isteğe bağlı)
        threat_nodes = []
        if threat_profile:
            threat_type = threat_profile.get("threat_type", {}).get("type", "UNKNOWN")
            threat_severity = threat_profile.get("threat_type", {}).get("severity", 0)
            
            threat_id = f"threat_{hashlib.md5(threat_type.encode()).hexdigest()[:8]}"
            
            threat_node = {
                "id": threat_id,
                "label": f"Tehdit: {threat_type}",
                "type": "threat",
                "size": 35,
                "color": self.color_map.get(self._severity_to_risk(threat_severity), "#FF0000"),
                "fill": "solid",
                "threat_type": threat_type,
                "severity": threat_severity
            }
            threat_nodes.append(threat_node)
            nodes.append(threat_node)
            
            threat_link = {
                "source": threat_id,
                "target": center_node["id"],
                "strength": 0.9,
                "distance": 150,
                "color": self.color_map.get(self._severity_to_risk(threat_severity), "#FF0000"),
                "opacity": 0.7,
                "width": 4,
                "label": "Threatens"
            }
            links.append(threat_link)
        
        # Radar metadata
        total_exposure = sum(self._estimate_records(b.get("name", "")) for b in breaches)
        
        radar_data = {
            "nodes": nodes,
            "links": links,
            "metadata": {
                "email": email,
                "total_breaches": len(breaches),
                "total_zombie_accounts": len(zombie_accounts) if zombie_accounts else 0,
                "total_records_exposed": total_exposure,
                "breach_types": list(set(b.get("name", "") for b in breaches)),
                "generated_at": datetime.now().isoformat(),
                "overall_risk_level": self._calculate_overall_risk(breaches, zombie_accounts)
            },
            "visualization_config": {
                "force_strength": -200,
                "center_force_strength": 0.1,
                "collision_force_strength": 50,
                "simulation_ticks": 300,
                "node_radius_scale": 2,
                "link_distance_range": [50, 200]
            }
        }
        
        return radar_data
    
    def _get_breach_risk_level(self, breach: Dict) -> str:
        """Breach'ün risk seviyesini belirle"""
        data_classes = breach.get("data_classes", [])
        
        critical_classes = [
            "Credit cards", "Bank account numbers", "Private messages",
            "Passwords", "Social media profiles", "Fotoğraflar", "Özel mesajlar"
        ]
        
        high_classes = [
            "Email addresses", "Phone numbers", "Dates of birth",
            "Physical addresses", "TCKN", "Şifre"
        ]
        
        critical_found = any(dc in critical_classes for dc in data_classes)
        high_found = any(dc in high_classes for dc in data_classes)
        
        if critical_found:
            return "CRITICAL"
        elif high_found:
            return "HIGH"
        elif len(data_classes) > 3:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _estimate_records(self, breach_name: str) -> int:
        """Sızıntı adından kayıt sayısı tahmini yapan sahte veri"""
        # Gerçek uygulamada API'den gelir
        estimates = {
            "LinkedIn": 700000000,
            "MySpace": 359000000,
            "Yahoo": 3000000000,
            "Facebook": 533000000,
            "Dropbox": 68000000,
            "Adobe": 153000000,
            "Adult FriendFinder": 412000000,
            "Twitter": 100000000,
            "Google Plus": 50000000,
        }
        
        for key, value in estimates.items():
            if key.lower() in breach_name.lower():
                return value
        
        return 1000000  # Varsayılan tahmin
    
    def _get_link_width(self, risk_level: str) -> int:
        """Risk seviyesine göre link kalınlığı"""
        width_map = {
            "CRITICAL": 6,
            "HIGH": 5,
            "MEDIUM": 4,
            "LOW": 2,
            "INFO": 1
        }
        return width_map.get(risk_level, 2)
    
    def _severity_to_risk(self, severity: float) -> str:
        """Severity score'unu risk seviyesine dönüştür"""
        if severity >= 85:
            return "CRITICAL"
        elif severity >= 70:
            return "HIGH"
        elif severity >= 50:
            return "MEDIUM"
        elif severity >= 25:
            return "LOW"
        else:
            return "INFO"
    
    def _calculate_overall_risk(self, breaches: List[Dict], zombie_accounts: Optional[List[Dict]]) -> str:
        """Genel risk seviyesini hesapla"""
        risk_scores = []
        
        for breach in breaches:
            risk_level = self._get_breach_risk_level(breach)
            if risk_level == "CRITICAL":
                risk_scores.append(85)
            elif risk_level == "HIGH":
                risk_scores.append(70)
            elif risk_level == "MEDIUM":
                risk_scores.append(50)
            else:
                risk_scores.append(25)
        
        if zombie_accounts:
            for zombie in zombie_accounts:
                if zombie.get("risk") == "high":
                    risk_scores.append(40)
                elif zombie.get("risk") == "medium":
                    risk_scores.append(25)
        
        avg_risk = sum(risk_scores) / len(risk_scores) if risk_scores else 0
        
        return self._severity_to_risk(avg_risk)


def create_d3_visualization_html(radar_data: Dict) -> str:
    """
    D3.js ile çalışacak HTML sayfası oluştur
    Frontend'de kullanılır
    """
    import json
    
    data_json = json.dumps(radar_data)
    
    html = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Aegis Nexus - Veri Radarı</title>
    <script src="https://d3js.org/d3.v7.min.js"></script>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: #0a0e27;
            color: #e0e0e0;
            margin: 0;
            padding: 20px;
        }}
        
        #radar {{
            width: 100%;
            height: 600px;
            background: #0f1419;
            border-radius: 8px;
            border: 1px solid #1e90ff;
            box-shadow: 0 0 30px rgba(30, 144, 255, 0.3);
        }}
        
        .radar-info {{
            margin-top: 20px;
            padding: 15px;
            background: #0f1419;
            border-radius: 8px;
            border: 1px solid #444;
        }}
        
        .info-row {{
            display: flex;
            justify-content: space-between;
            padding: 8px 0;
            border-bottom: 1px solid #333;
        }}
        
        .risk-critical {{ color: #FF0000; font-weight: bold; }}
        .risk-high {{ color: #FF6B00; font-weight: bold; }}
        .risk-medium {{ color: #FFA500; font-weight: bold; }}
        .risk-low {{ color: #FFD700; font-weight: bold; }}
        
        .node {{
            stroke: #fff;
            stroke-width: 2px;
            cursor: pointer;
        }}
        
        .link {{
            stroke-opacity: 0.6;
            fill: none;
        }}
    </style>
</head>
<body>
    <h1>🔴 Veri Radarı - E-posta Sızıntı Haritası</h1>
    <div id="radar"></div>
    
    <div class="radar-info">
        <div class="info-row">
            <span>E-posta:</span>
            <strong>{radar_data['metadata']['email']}</strong>
        </div>
        <div class="info-row">
            <span>Toplam Sızıntı:</span>
            <strong>{radar_data['metadata']['total_breaches']}</strong>
        </div>
        <div class="info-row">
            <span>Sızıntılı Kayıtlar:</span>
            <strong>{radar_data['metadata']['total_records_exposed']:,}</strong>
        </div>
        <div class="info-row">
            <span>Risk Seviyesi:</span>
            <strong class="risk-{radar_data['metadata']['overall_risk_level'].lower()}">{radar_data['metadata']['overall_risk_level']}</strong>
        </div>
    </div>
    
    <script>
        const radarData = {data_json};
        
        // D3.js visualization
        const width = document.getElementById('radar').clientWidth;
        const height = document.getElementById('radar').clientHeight;
        
        const svg = d3.select('#radar')
            .append('svg')
            .attr('width', width)
            .attr('height', height);
        
        // Simulation
        const simulation = d3.forceSimulation(radarData.nodes)
            .force('link', d3.forceLink(radarData.links)
                .id(d => d.id)
                .distance(d => d.distance))
            .force('charge', d3.forceManyBody().strength(-200))
            .force('center', d3.forceCenter(width / 2, height / 2));
        
        // Links
        const link = svg.selectAll('line')
            .data(radarData.links)
            .enter()
            .append('line')
            .attr('class', 'link')
            .attr('stroke', d => d.color)
            .attr('stroke-width', d => d.width)
            .attr('opacity', d => d.opacity);
        
        // Nodes
        const node = svg.selectAll('circle')
            .data(radarData.nodes)
            .enter()
            .append('circle')
            .attr('class', 'node')
            .attr('r', d => d.size)
            .attr('fill', d => d.color)
            .call(d3.drag()
                .on('start', dragstarted)
                .on('drag', dragged)
                .on('end', dragended));
        
        // Labels
        const labels = svg.selectAll('text')
            .data(radarData.nodes)
            .enter()
            .append('text')
            .text(d => d.label)
            .attr('font-size', '11px')
            .attr('fill', '#e0e0e0')
            .attr('text-anchor', 'middle')
            .attr('pointer-events', 'none');
        
        simulation.on('tick', () => {{
            link
                .attr('x1', d => d.source.x)
                .attr('y1', d => d.source.y)
                .attr('x2', d => d.target.x)
                .attr('y2', d => d.target.y);
            
            node
                .attr('cx', d => d.x)
                .attr('cy', d => d.y);
            
            labels
                .attr('x', d => d.x)
                .attr('y', d => d.y - d.size - 5);
        }});
        
        function dragstarted(event, d) {{
            if (!event.active) simulation.alphaTarget(0.3).restart();
            d.fx = d.x;
            d.fy = d.y;
        }}
        
        function dragged(event, d) {{
            d.fx = event.x;
            d.fy = event.y;
        }}
        
        function dragended(event, d) {{
            if (!event.active) simulation.alphaTarget(0);
            d.fx = null;
            d.fy = null;
        }}
    </script>
</body>
</html>
    """
    
    return html
