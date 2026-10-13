"""Session-bound CSRF tokens and baseline browser security headers."""

import hashlib
import secrets
from urllib.parse import urlsplit

from itsdangerous import BadSignature, SignatureExpired
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from app.auth import SESSION_COOKIE, serializer


def binding(request):
    return hashlib.sha256(request.cookies.get(SESSION_COOKIE, "").encode()).hexdigest()


class SecurityMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        request.state.csrf_token = serializer.dumps({"csrf": secrets.token_urlsafe(24), "binding": binding(request)})
        if request.url.path.startswith("/admin") and request.method in ("POST", "PUT", "PATCH", "DELETE"):
            origin = request.headers.get("origin") or request.headers.get("referer")
            if origin:
                actual, expected = urlsplit(origin), urlsplit(str(request.url))
                if (actual.scheme, actual.netloc) != (expected.scheme, expected.netloc):
                    return JSONResponse({"detail": "Cross-origin form rejected"}, status_code=403)
            await request.body()  # cache for downstream form parsing
            form = await request.form()
            token = form.get("csrf_token", "")
            try:
                data = serializer.loads(token, max_age=3600)
                valid = bool(data.get("csrf")) and data.get("binding") == binding(request)
            except (BadSignature, SignatureExpired, TypeError):
                valid = False
            if not valid:
                return JSONResponse({"detail": "CSRF token missing or expired; reload form"}, status_code=403)
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "same-origin"
        response.headers["X-Frame-Options"] = "DENY"
        # All panel scripts and styles are external; inline handlers are forbidden.
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'"
        )
        if request.url.scheme == "https":
            response.headers["Strict-Transport-Security"] = "max-age=31536000"
        if request.url.path.startswith("/admin"):
            response.headers["Cache-Control"] = "no-store"
        return response
