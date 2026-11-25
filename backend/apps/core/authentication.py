# backend/apps/core/authentication.py
import os
import jwt
from jwt import PyJWKClient
from rest_framework import authentication, exceptions


class SupabaseUser:
    """Lightweight authenticated principal backed by a Supabase JWT sub claim."""

    def __init__(self, user_id: str, email: str = "", role: str = "authenticated", claims: dict | None = None):
        self.id = str(user_id)
        self.pk = str(user_id)
        self.email = email
        self.role = role
        self.claims = claims or {}
        self.is_authenticated = True
        self.is_active = True


class SupabaseJWTAuthentication(authentication.BaseAuthentication):
    """Validates Bearer tokens issued by Supabase Auth using JWKS."""

    keyword = "Bearer"
    _jwks_client = None

    @classmethod
    def get_jwks_client(cls) -> PyJWKClient:
        if cls._jwks_client is None:
            supabase_url = os.environ.get("SUPABASE_URL", "").rstrip("/")
            if not supabase_url:
                raise exceptions.AuthenticationFailed("SUPABASE_URL is not configured.")
            jwks_url = f"{supabase_url}/auth/v1/.well-known/jwks.json"
            cls._jwks_client = PyJWKClient(jwks_url)
        return cls._jwks_client

    def authenticate(self, request):
        auth_header = authentication.get_authorization_header(request).decode("utf-8")
        if not auth_header:
            return None

        parts = auth_header.split()
        if len(parts) != 2 or parts[0] != self.keyword:
            raise exceptions.AuthenticationFailed("Invalid Authorization header format. Expected: Bearer <token>")

        token = parts[1]
        try:
            jwks_client = self.get_jwks_client()
            signing_key = jwks_client.get_signing_key_from_jwt(token)
            claims = jwt.decode(
                token,
                signing_key.key,
                algorithms=["RS256", "ES256"],
                options={"verify_aud": False},
            )
        except jwt.ExpiredSignatureError as exc:
            raise exceptions.AuthenticationFailed("Session token has expired.") from exc
        except jwt.PyJWTError as exc:
            raise exceptions.AuthenticationFailed(f"Invalid Supabase token: {exc}") from exc

        user_id = claims.get("sub")
        if not user_id:
            raise exceptions.AuthenticationFailed("Token missing subject (sub) claim.")

        user = SupabaseUser(
            user_id=user_id,
            email=claims.get("email", ""),
            role=claims.get("role", "authenticated"),
            claims=claims,
        )
        return (user, token)