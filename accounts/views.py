import base64
import hashlib
import secrets
from functools import wraps
from urllib.parse import urlencode

import jwt
import requests
from django.conf import settings
from django.shortcuts import redirect, render
from django.views.decorators.http import require_POST

from .cognito import verify_id_token


def _pkce_pair():
    verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(verifier.encode()).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b'=').decode()
    return verifier, challenge


def login_required(view):
    @wraps(view)
    def wrapper(request, *args, **kwargs):
        if 'user' not in request.session:
            return redirect('home')
        return view(request, *args, **kwargs)
    return wrapper


def home(request):
    if 'user' in request.session:
        return redirect('welcome')
    return render(request, 'home.html')


def login(request):
    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    verifier, challenge = _pkce_pair()
    request.session['oauth'] = {'state': state, 'nonce': nonce, 'verifier': verifier}

    params = {
        'client_id': settings.COGNITO_CLIENT_ID,
        'response_type': 'code',
        'scope': 'openid email profile',
        'redirect_uri': settings.COGNITO_REDIRECT_URI,
        'state': state,
        'nonce': nonce,
        'code_challenge': challenge,
        'code_challenge_method': 'S256',
    }
    return redirect(f'{settings.COGNITO_DOMAIN}/oauth2/authorize?{urlencode(params)}')


def callback(request):
    saved = request.session.pop('oauth', None)

    if 'error' in request.GET:
        msg = request.GET.get('error_description') or request.GET['error']
        return render(request, 'home.html', {'error': msg}, status=400)
    if not saved or request.GET.get('state') != saved['state']:
        return render(request, 'home.html', {'error': 'Invalid or expired login attempt.'}, status=400)
    code = request.GET.get('code')
    if not code:
        return render(request, 'home.html', {'error': 'No authorization code returned.'}, status=400)

    # Back-channel: exchange the one-time code for tokens
    data = {
        'grant_type': 'authorization_code',
        'client_id': settings.COGNITO_CLIENT_ID,
        'code': code,
        'redirect_uri': settings.COGNITO_REDIRECT_URI,
        'code_verifier': saved['verifier'],
    }
    auth = None
    if settings.COGNITO_CLIENT_SECRET:
        auth = (settings.COGNITO_CLIENT_ID, settings.COGNITO_CLIENT_SECRET)
    resp = requests.post(f'{settings.COGNITO_DOMAIN}/oauth2/token', data=data, auth=auth, timeout=10)
    if resp.status_code != 200:
        return render(request, 'home.html', {'error': 'Token exchange failed.'}, status=400)
    tokens = resp.json()

    try:
        claims = verify_id_token(tokens['id_token'], saved['nonce'])
    except (jwt.PyJWTError, KeyError):
        return render(request, 'home.html', {'error': 'Token verification failed.'}, status=400)

    request.session.cycle_key()  # new session ID after login (prevents session fixation)
    request.session['user'] = {
        'sub': claims['sub'],
        'email': claims.get('email', ''),
        'username': claims.get('cognito:username', ''),
        'claims': claims,
    }
    return redirect('welcome')


@login_required
def welcome(request):
    user = request.session['user']
    return render(request, 'welcome.html', {'user': user, 'claims': user['claims']})


@require_POST
def logout(request):
    request.session.flush()  # end the Django session
    params = {'client_id': settings.COGNITO_CLIENT_ID, 'logout_uri': settings.COGNITO_LOGOUT_URI}
    return redirect(f'{settings.COGNITO_DOMAIN}/logout?{urlencode(params)}')  # end the Cognito session