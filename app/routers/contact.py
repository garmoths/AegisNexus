import logging

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(tags=["contact"])


class ContactForm(BaseModel):
    name: str = Field(..., min_length=1, max_length=120)
    email: str = Field(..., min_length=5, max_length=320)
    message: str = Field(..., min_length=10, max_length=4000)


@router.post("/api/contact")
@router.post("/api/v2/contact")
def submit_contact(form: ContactForm):
    """No delivery channel exists yet; never log private form content or claim delivery."""
    raise HTTPException(503, 'İletişim kanalı henüz yapılandırılmadı. Mesajınız gönderilmedi veya kaydedilmedi.')
