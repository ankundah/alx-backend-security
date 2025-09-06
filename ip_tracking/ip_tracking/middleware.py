import requests
from django.utils.timezone import now
from django.core.cache import cache
from django.http import HttpResponseForbidden
from ipware import get_client_ip
from .models import RequestLog, BlockedIP

class IPTrackingMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Get client IP using ipware
        ip, _ = get_client_ip(request)
        if not ip:
            ip = "0.0.0.0"  # fallback

        # Block blacklisted IPs
        if BlockedIP.objects.filter(ip_address=ip).exists():
            return HttpResponseForbidden("Your IP has been blocked.")

        # Try fetching location from cache first
        location = cache.get(f"geo_{ip}")
        if not location:
            try:
                # Use ip-api.com free service for geolocation
                response = requests.get(f"http://ip-api.com/json/{ip}")
                data = response.json()

                if data.get("status") == "success":
                    location = {
                        "country": data.get("country", "Unknown"),
                        "city": data.get("city", "Unknown")
                    }
                else:
                    location = {"country": "Unknown", "city": "Unknown"}

            except Exception:
                location = {"country": "Unknown", "city": "Unknown"}

            # Cache location for 24 hours
            cache.set(f"geo_{ip}", location, timeout=60 * 60 * 24)

        # Save request log to DB
        RequestLog.objects.create(
            ip_address=ip,
            path=request.path,
            timestamp=now(),
            country=location["country"],
            city=location["city"]
        )

        return self.get_response(request)
