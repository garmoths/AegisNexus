"""
02 - Honeypot Module & IOC Collector
IP Avcısı ve Indicator of Compromise (IoC) toplayıcı modülü
"""
from .router import router
from .ioc_api import router as ioc_router

__all__ = ["router", "ioc_router"]
