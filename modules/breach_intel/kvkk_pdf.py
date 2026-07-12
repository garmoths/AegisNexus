"""
modules/breach_intel/kvkk_pdf.py

KVKK 6698 Sayılı Kanun uyumlu kişisel veri ihlali başvuru belgesi PDF olarak üretir.
reportlab kütüphanesi gerektirir (pip install reportlab).

Fallback: reportlab yüklü değilse metin tabanlı özet döner.
"""

from __future__ import annotations

import io
import logging
import os
import re
from datetime import date, datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# ─── Unicode font registration (Türkçe karakter desteği) ──
_TR_FONT_REGULAR: str | None = None
_TR_FONT_BOLD: str | None = None

_REGULAR_CANDIDATES = [
    "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    "/usr/share/fonts/truetype/freefont/FreeSans.ttf",
    "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf",
    "/usr/share/fonts/truetype/ubuntu/Ubuntu-R.ttf",
    "/usr/share/fonts/truetype/noto/NotoSans-Regular.ttf",
    "/usr/share/fonts/truetype/noto/NotoSans.ttf",
]
_BOLD_CANDIDATES = [
    "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
    "/usr/share/fonts/truetype/freefont/FreeSansBold.ttf",
    "/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf",
    "/usr/share/fonts/truetype/ubuntu/Ubuntu-B.ttf",
    "/usr/share/fonts/truetype/noto/NotoSans-Bold.ttf",
]


def _register_tr_fonts() -> tuple[str, str]:
    """Register a Unicode-capable TTF font pair for Turkish characters.
    Returns (regular_font_name, bold_font_name).
    """
    global _TR_FONT_REGULAR, _TR_FONT_BOLD
    if _TR_FONT_REGULAR:
        return _TR_FONT_REGULAR, _TR_FONT_BOLD or "Helvetica-Bold"

    try:
        from reportlab.pdfbase import pdfmetrics
        from reportlab.pdfbase.ttfonts import TTFont
    except ImportError:
        return "Helvetica", "Helvetica-Bold"

    for path in _REGULAR_CANDIDATES:
        if os.path.exists(path):
            try:
                pdfmetrics.registerFont(TTFont("TRFont", path))
                _TR_FONT_REGULAR = "TRFont"
                logger.info(f"[KVKK PDF] Türkçe font kaydedildi: {path}")
                break
            except Exception as e:
                logger.debug(f"[KVKK PDF] Font kayıt hatası {path}: {e}")

    for path in _BOLD_CANDIDATES:
        if os.path.exists(path):
            try:
                pdfmetrics.registerFont(TTFont("TRFontBold", path))
                _TR_FONT_BOLD = "TRFontBold"
                break
            except Exception as e:
                logger.debug(f"[KVKK PDF] Bold font kayıt hatası {path}: {e}")

    regular = _TR_FONT_REGULAR or "Helvetica"
    bold = _TR_FONT_BOLD or "Helvetica-Bold"
    if not _TR_FONT_REGULAR:
        logger.warning("[KVKK PDF] Unicode font bulunamadı, Helvetica kullanılıyor (Türkçe karakter sorunları olabilir)")
    return regular, bold

# ─── Türkçe ay adları ────────────────────────────────────
_TR_MONTHS = [
    "", "Ocak", "Şubat", "Mart", "Nisan", "Mayıs", "Haziran",
    "Temmuz", "Ağustos", "Eylül", "Ekim", "Kasım", "Aralık",
]

def _tr_date(d: date) -> str:
    return f"{d.day} {_TR_MONTHS[d.month]} {d.year}"


def _breach_data_classes_tr(classes: List[str]) -> str:
    mapping = {
        "Passwords": "Şifreler",
        "Email addresses": "E-posta Adresleri",
        "Usernames": "Kullanıcı Adları",
        "Phone numbers": "Telefon Numaraları",
        "Physical addresses": "Fiziksel Adresler",
        "Dates of birth": "Doğum Tarihleri",
        "Names": "İsimler",
        "IP addresses": "IP Adresleri",
        "Credit cards": "Kredi Kartı Bilgileri",
        "Geographic locations": "Coğrafi Konum",
        "Browser user agent details": "Tarayıcı Bilgileri",
        "Social media profiles": "Sosyal Medya Profilleri",
        "Employers": "İşveren Bilgileri",
    }
    tr_classes = [mapping.get(c, c) for c in classes]
    return ", ".join(tr_classes) if tr_classes else "Bilinmiyor"


def generate_kvkk_pdf(
    email: str,
    breaches: List[Dict[str, Any]],
    applicant_name: Optional[str] = None,
) -> Dict[str, Any]:
    """
    KVKK başvuru belgesini PDF olarak üretir.

    Args:
        email: Başvuru sahibinin e-posta adresi.
        breaches: HIBP'ten gelen sızıntı listesi.
        applicant_name: Başvurucu adı/soyadı (opsiyonel).

    Returns:
        {
            "pdf_bytes": bytes,          # PDF içeriği (Base64 ile serileştirmek için)
            "pdf_base64": str,           # Base64 kodlu PDF
            "filename": str,
            "method": "reportlab" | "text_fallback",
            "breach_count": int,
        }
    """
    try:
        return _generate_with_reportlab(email, breaches, applicant_name)
    except ImportError:
        logger.warning("[KVKK PDF] reportlab yüklü değil, metin fallback kullanılıyor.")
        return _generate_text_fallback(email, breaches, applicant_name)
    except Exception as exc:
        logger.error(f"[KVKK PDF] PDF üretim hatası: {exc}", exc_info=True)
        return _generate_text_fallback(email, breaches, applicant_name)


def _generate_with_reportlab(
    email: str,
    breaches: List[Dict[str, Any]],
    applicant_name: Optional[str],
) -> Dict[str, Any]:
    import base64
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm
    from reportlab.platypus import (
        HRFlowable, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle, Frame, PageTemplate
    )
    from reportlab.platypus.flowables import KeepTogether
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT

    today = date.today()
    buffer = io.BytesIO()

    # ─── Colors ───────────────────────────────────────────
    C_NAVY   = colors.HexColor("#0f1629")
    C_CYAN   = colors.HexColor("#00d4ff")
    C_DARK   = colors.HexColor("#080c14")
    C_DANGER = colors.HexColor("#ef4444")
    C_WARN   = colors.HexColor("#f59e0b")
    C_OK     = colors.HexColor("#22c55e")
    C_GRAY1  = colors.HexColor("#f5f8fc")
    C_GRAY2  = colors.HexColor("#dce6f0")
    C_TEXT   = colors.HexColor("#1a202c")
    C_MUTED  = colors.HexColor("#64748b")

    def _add_header_footer(canvas, doc):
        canvas.saveState()
        w, h = A4
        # ── header bar ──────────────────────────────────────────
        canvas.setFillColor(C_NAVY)
        canvas.rect(0, h - 1.8 * cm, w, 1.8 * cm, fill=1, stroke=0)
        canvas.setFillColor(C_CYAN)
        canvas.rect(0, h - 1.85 * cm, w, 0.08 * cm, fill=1, stroke=0)  # cyan accent line
        canvas.setFont("Helvetica-Bold", 13)
        canvas.setFillColor(colors.white)
        canvas.drawString(2.5 * cm, h - 1.25 * cm, "AegisNexus")
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(C_CYAN)
        canvas.drawString(2.5 * cm + 90, h - 1.22 * cm, "KVKK Veri İhlali Başvuru Belgesi")
        canvas.setFont("Helvetica", 7.5)
        canvas.setFillColor(colors.white)
        canvas.drawRightString(w - 2.5 * cm, h - 1.25 * cm, f"Tarih: {_tr_date(today)}")
        # ── footer ───────────────────────────────────────────────
        canvas.setFillColor(C_GRAY1)
        canvas.rect(0, 0, w, 1.1 * cm, fill=1, stroke=0)
        canvas.setFillColor(C_GRAY2)
        canvas.rect(0, 1.1 * cm, w, 0.04 * cm, fill=1, stroke=0)
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(C_MUTED)
        canvas.drawString(2.5 * cm, 0.5 * cm, "Bu rapor AegisNexus platformu tarafından oluşturulmuştur.")
        canvas.drawRightString(w - 2.5 * cm, 0.5 * cm, f"Sayfa {doc.page}")
        canvas.restoreState()

    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=2.5 * cm,
        rightMargin=2.5 * cm,
        topMargin=2.8 * cm,
        bottomMargin=2.0 * cm,
        title="KVKK Kişisel Veri İhlali Başvurusu",
    )

    font_reg, font_bold = _register_tr_fonts()

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "TitleStyle", parent=styles["Title"],
        fontName=font_bold,
        fontSize=16, spaceAfter=4, textColor=C_NAVY, alignment=TA_LEFT,
    )
    heading_style = ParagraphStyle(
        "HeadingStyle", parent=styles["Heading2"],
        fontName=font_bold,
        fontSize=10, spaceBefore=14, spaceAfter=4, textColor=C_NAVY,
        borderPadding=(0, 0, 4, 0),
    )
    body_style = ParagraphStyle(
        "BodyStyle", parent=styles["Normal"],
        fontName=font_reg,
        fontSize=9.5, spaceAfter=4, leading=14, textColor=C_TEXT,
    )
    bold_style = ParagraphStyle(
        "BoldStyle", parent=body_style, fontName=font_bold,
    )
    warning_style = ParagraphStyle(
        "WarningStyle", parent=body_style,
        fontName=font_reg,
        backColor=colors.HexColor("#fff8e1"),
        borderColor=C_WARN,
        borderWidth=1.5, borderPadding=8,
        spaceAfter=8, textColor=C_TEXT,
    )
    muted_style = ParagraphStyle(
        "MutedStyle", parent=body_style,
        fontName=font_reg, fontSize=8, textColor=C_MUTED,
    )

    story = []

    # ── Banner / Başlık ────────────────────────────────────
    story.append(Spacer(1, 0.2 * cm))
    story.append(Paragraph("KİŞİSEL VERİLERİN KORUNMASI KANUNU", title_style))
    story.append(Paragraph("6698 Sayılı KVKK — Kişisel Veri İhlali Başvuru Belgesi", ParagraphStyle(
        "SubTitle", parent=body_style, fontSize=10, textColor=C_MUTED, spaceAfter=8,
    )))
    story.append(HRFlowable(width="100%", thickness=2, color=C_CYAN, spaceAfter=8))
    # Risk özet badge
    breach_count = len(breaches)
    severity_color = C_DANGER if breach_count >= 5 else (C_WARN if breach_count >= 2 else C_OK)
    badge_data = [[f"{breach_count} Veri İhlali Tespit Edildi", "Acil İnceleme Önerilir" if breach_count >= 3 else "İnceleme Önerilir"]]
    badge_t = Table(badge_data, colWidths=[8 * cm, 8.5 * cm])
    badge_t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, 0), severity_color),
        ("BACKGROUND", (1, 0), (1, 0), C_NAVY),
        ("TEXTCOLOR", (0, 0), (-1, -1), colors.white),
        ("FONT", (0, 0), (0, 0), font_bold, 11),
        ("FONT", (1, 0), (1, 0), font_reg, 9),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("LEFTPADDING", (0, 0), (-1, -1), 12),
        ("ALIGN", (0, 0), (0, 0), "LEFT"),
        ("ALIGN", (1, 0), (1, 0), "RIGHT"),
        ("RIGHTPADDING", (1, 0), (1, 0), 12),
        ("ROUNDEDCORNERS", [4, 4, 4, 4]),
    ]))
    story.append(badge_t)
    story.append(Spacer(1, 0.4 * cm))

    # Başvuru bilgileri tablosu
    story.append(Paragraph("BAŞVURU BİLGİLERİ", heading_style))
    info_data = [
        ["Başvuru Tarihi:", _tr_date(today)],
        ["Başvurucu E-posta:", email],
        ["Başvurucu Adı/Soyadı:", applicant_name or "(Lütfen doldurunuz)"],
        ["Başvuru Türü:", "Kişisel Veri İhlali Bildirimi"],
        ["Kanun Dayanağı:", "6698 Sayılı KVKK Madde 11"],
        ["Başvuru Makamı:", "Kişisel Verileri Koruma Kurumu (KVKK)"],
        ["Başvuru Adresi:", "kvkk.gov.tr — Başvuru Formu"],
    ]
    t = Table(info_data, colWidths=[5.5 * cm, 11 * cm])
    t.setStyle(TableStyle([
        ("FONT", (0, 0), (0, -1), font_bold),
        ("FONT", (1, 0), (1, -1), font_reg),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [colors.white, colors.HexColor("#f5f5f5")]),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#bdbdbd")),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(t)
    story.append(Spacer(1, 0.4 * cm))

    # İhlal özeti
    story.append(Paragraph("VERİ İHLALİ ÖZET BİLGİSİ", heading_style))
    story.append(Paragraph(
        f"<b>{email}</b> e-posta adresine ait kişisel veriler, aşağıda listelenen "
        f"<b>{len(breaches)} farklı veri ihlalinde</b> tespit edilmiştir. "
        "Bu ihlaller HaveIBeenPwned (HIBP) küresel veri ihlali veritabanı aracılığıyla doğrulanmıştır.",
        body_style,
    ))
    story.append(Spacer(1, 0.3 * cm))

    # İhlal listesi tablosu
    story.append(Paragraph("İHLAL DETAYLARI", heading_style))
    breach_header = ["#", "Platform / Kuruluş", "İhlal Tarihi", "Etkilenen Veriler"]
    breach_rows = [breach_header]
    for i, b in enumerate(breaches, start=1):
        breach_date = b.get("BreachDate") or b.get("breach_date") or "Bilinmiyor"
        data_classes = b.get("DataClasses") or b.get("data_classes") or []
        company = b.get("Name") or b.get("name") or b.get("domain") or "Bilinmiyor"
        breach_rows.append([
            str(i),
            company[:40],
            breach_date,
            _breach_data_classes_tr(data_classes)[:80],
        ])

    bt = Table(breach_rows, colWidths=[0.7 * cm, 5 * cm, 3.5 * cm, 7.3 * cm])
    table_cmds = [
        ("BACKGROUND", (0, 0), (-1, 0), C_NAVY),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONT", (0, 0), (-1, 0), font_bold),
        ("FONT", (0, 1), (-1, -1), font_reg),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, C_GRAY1]),
        ("GRID", (0, 0), (-1, -1), 0.4, C_GRAY2),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]
    # Color-code rows by recency (recent = red, older = yellow/green)
    for row_idx, b in enumerate(breaches, start=1):
        bd = b.get("BreachDate") or b.get("breach_date") or ""
        try:
            breach_year = int(str(bd)[:4])
            row_color = C_DANGER if breach_year >= 2022 else (C_WARN if breach_year >= 2018 else C_OK)
        except (ValueError, TypeError):
            row_color = C_MUTED
        table_cmds.append(("TEXTCOLOR", (2, row_idx), (2, row_idx), row_color))
        table_cmds.append(("FONT", (2, row_idx), (2, row_idx), font_bold))
    bt.setStyle(TableStyle(table_cmds))
    story.append(bt)
    story.append(Spacer(1, 0.4 * cm))

    # Talep bölümü
    story.append(Paragraph("BAŞVURU TALEPLERİ", heading_style))
    requests_text = [
        "1. Kişisel verilerimin hangi üçüncü taraflarla paylaşıldığının tarafıma bildirilmesi (Madde 11/1-d)",
        "2. İhlale konu verilerin ilgili platformlardan silinmesi veya anonimleştirilmesi (Madde 7)",
        "3. Bu ihlaller nedeniyle uğradığım/uğrayabileceğim zararların tazmininin sağlanması (Madde 14)",
        "4. Veri sorumlusunun KVKK'ya bildirim yükümlülüğünü yerine getirip getirmediğinin denetlenmesi",
        "5. Gerekli idari ve teknik tedbirlerin alınması için veri sorumlularına yaptırım uygulanması",
    ]
    for req_text in requests_text:
        story.append(Paragraph(req_text, body_style))
    story.append(Spacer(1, 0.3 * cm))

    # Uyarı
    story.append(Paragraph(
        "⚠️ Bu belge Aegis Nexus platformu tarafından otomatik olarak oluşturulmuştur. "
        "Başvuru yapmadan önce bilgileri doğrulayınız. KVKK başvurusu için kvkk.gov.tr adresini kullanınız.",
        warning_style,
    ))

    # İmza bölümü
    story.append(Spacer(1, 1 * cm))
    sig_data = [
        ["Başvurucu İmzası:", ""],
        ["Tarih:", _tr_date(today)],
    ]
    st = Table(sig_data, colWidths=[5.5 * cm, 11 * cm])
    st.setStyle(TableStyle([
        ("FONT", (0, 0), (0, -1), font_bold),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#bdbdbd")),
        ("TOPPADDING", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
    ]))
    story.append(st)

    doc.build(story, onFirstPage=_add_header_footer, onLaterPages=_add_header_footer)
    pdf_bytes = buffer.getvalue()
    pdf_b64 = base64.b64encode(pdf_bytes).decode("utf-8")

    filename = f"kvkk_basvuru_{email.replace('@', '_at_').replace('.', '_')}_{today.isoformat()}.pdf"

    return {
        "pdf_bytes": pdf_bytes,
        "pdf_base64": pdf_b64,
        "filename": filename,
        "method": "reportlab",
        "breach_count": len(breaches),
    }


def _generate_text_fallback(
    email: str,
    breaches: List[Dict[str, Any]],
    applicant_name: Optional[str],
) -> Dict[str, Any]:
    """reportlab yoksa düz metin özet döner."""
    import base64

    today = date.today()
    lines = [
        "KİŞİSEL VERİLERİN KORUNMASI KANUNU (6698)",
        "Veri İhlali Başvuru Özeti",
        "=" * 50,
        f"Tarih: {_tr_date(today)}",
        f"E-posta: {email}",
        f"Başvurucu: {applicant_name or '(Doldurunuz)'}",
        "",
        f"Toplam {len(breaches)} ihlal tespit edildi:",
    ]
    for i, b in enumerate(breaches, 1):
        company = b.get("Name") or b.get("name") or b.get("domain") or "Bilinmiyor"
        breach_date = b.get("BreachDate") or b.get("breach_date") or "Bilinmiyor"
        data_classes = b.get("DataClasses") or b.get("data_classes") or []
        lines.append(f"  {i}. {company} ({breach_date}) — {_breach_data_classes_tr(data_classes)}")
    lines += [
        "",
        "TALEPLER: Veri silinmesi, bildirim, tazminat (KVKK Madde 7, 11, 14)",
        "Başvuru: kvkk.gov.tr",
    ]
    text = "\n".join(lines)
    text_bytes = text.encode("utf-8")
    filename = f"kvkk_basvuru_{email.replace('@', '_at_').replace('.', '_')}_{today.isoformat()}.txt"

    return {
        "pdf_bytes": text_bytes,
        "pdf_base64": base64.b64encode(text_bytes).decode("utf-8"),
        "filename": filename,
        "method": "text_fallback",
        "breach_count": len(breaches),
    }
