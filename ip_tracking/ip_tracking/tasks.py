from celery import shared_task
from django.utils import timezone
from datetime import timedelta
from .models import RequestLog, SuspiciousIP

SENSITIVE_PATHS = ['/admin', '/login']

@shared_task
def detect_anomalies():
    """Detect IPs making too many requests or hitting sensitive paths."""
    now = timezone.now()
    one_hour_ago = now - timedelta(hours=1)

    # Find IPs with more than 100 requests in the last hour
    high_volume_ips = (
        RequestLog.objects
        .filter(timestamp__gte=one_hour_ago)
        .values('ip_address')
        .annotate(count=models.Count('ip_address'))
        .filter(count__gt=100)
    )

    for ip in high_volume_ips:
        SuspiciousIP.objects.get_or_create(
            ip_address=ip['ip_address'],
            reason=f"High traffic: {ip['count']} requests in the last hour."
        )

    # Find IPs accessing sensitive paths repeatedly
    sensitive_hits = (
        RequestLog.objects
        .filter(path__in=SENSITIVE_PATHS, timestamp__gte=one_hour_ago)
        .values('ip_address')
        .annotate(count=models.Count('ip_address'))
        .filter(count__gt=10)
    )

    for ip in sensitive_hits:
        SuspiciousIP.objects.get_or_create(
            ip_address=ip['ip_address'],
            reason=f"Sensitive path probing: {ip['count']} hits in the last hour."
        )

    return f"Detected {len(high_volume_ips) + len(sensitive_hits)} suspicious IPs."
