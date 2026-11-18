"""Real Unicode PDF reports in the shared data directory."""
import os
import tempfile
from html import escape
from pathlib import Path

from app.config import get_settings


def generate_pdf(report):
    import reportlab
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer
    font_paths = [get_settings().pdf_font_path, '/usr/share/fonts/truetype/liberation2/LiberationSans-Regular.ttf',
                  '/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf',
                  '/System/Library/Fonts/Supplemental/Arial.ttf', str(Path(reportlab.__file__).parent / 'fonts/Vera.ttf')]
    font_path = next((p for p in font_paths if p and Path(p).is_file()), None)
    if font_path is None:
        raise RuntimeError('Türkçe PDF fontu bulunamadı.')
    if 'AegisReport' not in pdfmetrics.getRegisteredFontNames():
        pdfmetrics.registerFont(TTFont('AegisReport', font_path))
    directory = Path(get_settings().pdf_output_dir)
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / f'rapor_{report.id}.pdf'
    styles = getSampleStyleSheet()
    for style in styles.byName.values():
        style.fontName = 'AegisReport'
        style.leading = 17
        style.textColor = colors.HexColor('#172033')
    elements = [Paragraph('AegisNexus Güvenlik Raporu', styles['Title']), Spacer(1, 16)]
    fields = [('Rapor', str(report.id)), ('Tarih', str(report.created_at)),
              ('Olay anlatımı', report.user_description), ('Korunma planı', report.protection_plan or 'Analiz kullanılamıyor.')]
    for title, value in fields:
        elements += [Paragraph(escape(title), styles['Heading2']), Paragraph(escape(str(value)).replace('\n', '<br/>'), styles['BodyText']), Spacer(1, 12)]
    descriptor, temporary = tempfile.mkstemp(prefix='report-', suffix='.pdf', dir=directory)
    os.close(descriptor)
    try:
        SimpleDocTemplate(temporary, pagesize=A4, leftMargin=45, rightMargin=45, topMargin=45, bottomMargin=45).build(elements)
        os.replace(temporary, target)
    finally:
        Path(temporary).unlink(missing_ok=True)
    return str(target)
