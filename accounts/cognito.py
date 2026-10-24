import jwt
from django.conf import settings

_jwks_client = None


def _client():
    global _jwks_client
    if _jwks_client is None:
        _jwks_client = jwt.PyJWKClient(settings.COGNITO_JWKS_URL)
    return _jwks_client


def verify_id_token(token, expected_nonce):
    """Verify signature, issuer, audience and expiry, then token_use and nonce."""
    signing_key = _client().get_signing_key_from_jwt(token)
    claims = jwt.decode(
        token,
        signing_key.key,
        algorithms=['RS256'],
        audience=settings.COGNITO_CLIENT_ID,
        issuer=settings.COGNITO_ISSUER,
    )
    if claims.get('token_use') != 'id':
        raise jwt.InvalidTokenError('Not an ID token')
    if claims.get('nonce') != expected_nonce:
        raise jwt.InvalidTokenError('Nonce mismatch')
    return claims