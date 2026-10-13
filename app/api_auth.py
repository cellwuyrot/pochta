"""Bearer-token authentication for the public REST API.

Extracted from ``routes_api`` so that every API router can share one
implementation instead of reaching for a neighbour module's private helpers.

Two kinds of token are accepted:

* a **per-site key** (``sm_…``, shown in the admin panel) which scopes the caller
  to exactly that site;
* the optional **global key** (``API_KEY`` in .env) which is admin-scoped and may
  act on any configured site, but must then name the site explicitly.
"""

from dataclasses import dataclass

from fastapi import Depends, Header, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import get_db
from app.domain_util import normalize_domain
from app.models import Site

# What each kind of token is allowed to do. Exposed through GET /api/me so a
# client can show the user what their key grants instead of guessing.
SITE_SCOPES: tuple[str, ...] = (
    "emails:send",
    "domains:read",
    "webhooks:manage",
    "providers:manage",
)
GLOBAL_SCOPES: tuple[str, ...] = ("*",)


@dataclass(frozen=True)
class ApiIdentity:
    """Who is behind the bearer token on this request.

    ``kind`` is ``"site"`` (a per-site key, scoped to ``site``) or ``"global"``
    (the admin-scoped ``API_KEY``, which has no implicit site).
    """

    kind: str
    site: Site | None
    scopes: tuple[str, ...]

    @property
    def is_global(self) -> bool:
        return self.kind == "global"


def extract_token(authorization: str) -> str:
    """Pull the token out of an Authorization header value."""
    if authorization.startswith("Bearer "):
        return authorization[7:]
    if authorization.startswith("sm_"):
        return authorization
    return ""


def verify_api_key(authorization: str = Header(default="")) -> str:
    """Require a bearer token on every API call.

    Authentication is ALWAYS enforced: a request without a token is rejected.
    Which site the token is allowed to act on is decided later, once the target
    is known.
    """
    token = extract_token(authorization)
    if not token:
        raise HTTPException(
            status_code=401,
            detail="Missing API key. Use header: Authorization: Bearer sm_your_key",
        )
    return token


def is_global_key(token: str) -> bool:
    """True if the token matches the configured non-empty global admin key."""
    return bool(settings.api_key) and token == settings.api_key


async def resolve_site_by_key(db: AsyncSession, token: str) -> Site | None:
    """Find the active site whose per-site API key is ``token``."""
    if not token:
        return None
    return (
        await db.execute(select(Site).where(Site.api_key == token, Site.is_active.is_(True)))
    ).scalar_one_or_none()


async def authenticated_identity(
    db: AsyncSession = Depends(get_db),
    auth_token: str = Depends(verify_api_key),
) -> ApiIdentity:
    """Resolve and VALIDATE the token, without needing a target site.

    Use this on endpoints that are not about one specific site — ``/api/me`` and
    the domain listing. ``verify_api_key`` alone only proves the header was
    non-empty; it deliberately defers the real comparison to "once the target site
    is known". Endpoints that never reach that point were therefore accepting any
    ``Authorization: Bearer anything``, so validation has to happen here.

    The global key is checked first: a site whose key happens to equal API_KEY
    must not silently downgrade the caller to site scope.
    """
    if is_global_key(auth_token):
        return ApiIdentity(kind="global", site=None, scopes=GLOBAL_SCOPES)

    site = await resolve_site_by_key(db, auth_token)
    if site:
        return ApiIdentity(kind="site", site=site, scopes=SITE_SCOPES)

    raise HTTPException(
        status_code=401,
        detail="Invalid API key. Use the key from your site's admin panel (Сайты → API ключ).",
    )


async def authorized_site(
    site_domain: str | None = None,
    db: AsyncSession = Depends(get_db),
    auth_token: str = Depends(verify_api_key),
) -> Site:
    """Resolve the single site this request is authorised to act on.

    A per-site key resolves to its own site; passing ``site_domain`` that names a
    different site is refused rather than silently ignored. The global key must
    supply ``site_domain`` because it has no implicit site of its own.
    """
    if site_domain:
        try:
            site_domain = normalize_domain(site_domain)
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
    site = await resolve_site_by_key(db, auth_token)
    if site:
        if site_domain and site_domain.lower() != site.domain.lower():
            raise HTTPException(
                status_code=403,
                detail=f"This API key is scoped to {site.domain}, not {site_domain}.",
            )
        return site

    if not is_global_key(auth_token):
        raise HTTPException(
            status_code=401,
            detail="Invalid API key. Use the key from your site's admin panel (Сайты → API ключ).",
        )

    if not site_domain:
        raise HTTPException(
            status_code=400,
            detail="The global API key must name a site: add ?site_domain=example.com",
        )
    site = (
        await db.execute(
            select(Site).where(Site.domain == site_domain, Site.is_active.is_(True))
        )
    ).scalar_one_or_none()
    if not site:
        raise HTTPException(
            status_code=404,
            detail=f"No active site configured for '{site_domain}'.",
        )
    return site
