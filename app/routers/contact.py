import logging

from fastapi import APIRouter
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(tags=["contact"])


class ContactForm(BaseModel):
    name: str = Field(..., min_length=1, max_length=120)
    email: str = Field(..., min_length=5, max_length=320)
    message: str = Field(..., min_length=10, max_length=4000)


@router.post("/api/contact")
def submit_contact(form: ContactForm):
    """Mesaj sunucu günlüğüne yazılır; e-posta gönderimi yoktur (ileride SMTP eklenebilir)."""
    logger.info("İletişim formu | %s <%s> | %s", form.name, form.email, form.message[:300])
    return {
        "ok": True,
        "mesaj": "Mesajınız alındı. En kısa sürede size dönüş yapılır.",
    }
