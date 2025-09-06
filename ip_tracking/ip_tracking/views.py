from django.http import JsonResponse
from django.contrib.auth import authenticate, login
from ratelimit.decorators import ratelimit
from django.conf import settings

# Sensitive login view with rate limiting
@ratelimit(key='ip', rate=settings.RATE_LIMITS["ANONYMOUS"], method='POST', block=True)
def login_view(request):
    """
    Simple login view to demonstrate rate limiting.
    Anonymous users = 5 req/min.
    """
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')

        user = authenticate(request, username=username, password=password)
        if user:
            login(request, user)
            return JsonResponse({"message": "Login successful!"})
        return JsonResponse({"error": "Invalid credentials"}, status=401)

    return JsonResponse({"message": "Send a POST request to login."})

@ratelimit(key='user_or_ip', rate=settings.RATE_LIMITS["AUTHENTICATED"], method='GET', block=True)
def profile_view(request):
    """
    Authenticated users = 10 req/min.
    Anonymous users fallback to IP-based limit.
    """
    if not request.user.is_authenticated:
        return JsonResponse({"error": "Unauthorized"}, status=401)

    return JsonResponse({
        "username": request.user.username,
        "email": request.user.email
    })

