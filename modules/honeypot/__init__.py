"""
02 - Honeypot Module & IOC Collector
IP Avcısı ve Indicator of Compromise (IoC) toplayıcı modülü
"""
from .ioc_api import router as ioc_router
from .router import router

__all__ = ["router", "ioc_router"]
