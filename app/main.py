import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from app import __version__
from app.config import settings
from app.database import engine, migrate_add_api_key, migrate_add_dkim, migrate_hardening, seed_admin_user
from app.models import Base
from app.outbox import start_outbox_worker, stop_outbox_worker
from app.routes_admin import router as admin_router
from app.routes_admin_providers import router as admin_providers_router
from app.routes_admin_webhooks import router as admin_webhooks_router
from app.routes_api import router as api_router
from app.routes_mailboxes import admin_router as mailbox_admin_router
from app.routes_mailboxes import api_router as mailbox_api_router
from app.routes_outbox import router as outbox_router
from app.routes_providers import router as providers_router
from app.routes_webhooks import router as webhooks_router
from app.security import SecurityMiddleware
from app.smtp_server import start_smtp_server, stop_smtp_server
from app.webhook_service import start_webhook_worker, stop_webhook_worker

_BASE_DIR = Path(__file__).resolve().parent

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    await migrate_add_api_key()
    await migrate_add_dkim()
    await migrate_hardening()
    await seed_admin_user()
    logger.info("Database tables ready")

    start_smtp_server()
    logger.info("SMTP server running on port %d", settings.smtp_port)

    start_webhook_worker()
    start_outbox_worker()

    yield

    await stop_outbox_worker()
    await stop_webhook_worker()
    stop_smtp_server()
    await engine.dispose()
    logger.info("Shutdown complete")


app = FastAPI(
    title="SMTP Service",
    version=__version__,
    lifespan=lifespan,
    # Swagger UI enumerates the whole API surface; keep it off unless explicitly enabled.
    docs_url="/api/docs" if settings.api_docs_enabled else None,
    redoc_url=None,
    openapi_url="/api/openapi.json" if settings.api_docs_enabled else None,
)

_static_dir = _BASE_DIR / "static"
_static_dir.mkdir(exist_ok=True)
app.add_middleware(SecurityMiddleware)

app.mount("/static", StaticFiles(directory=str(_static_dir)), name="static")

app.include_router(api_router)
app.include_router(outbox_router)
app.include_router(webhooks_router)
app.include_router(providers_router)
app.include_router(admin_router)
app.include_router(admin_providers_router)
app.include_router(admin_webhooks_router)
app.include_router(mailbox_admin_router)
app.include_router(mailbox_api_router)


@app.get("/")
async def root(request: Request):
    if request.headers.get("accept", "").startswith("application/json"):
        return JSONResponse({
            "service": "SMTP Service",
            "version": __version__,
            "endpoints": {
                "send_email": "POST /api/emails",
                "webhooks": "GET/POST /api/webhooks",
                "providers": "GET/POST /api/providers",
                "health": "GET /api/health",
                "docs": "GET /api/docs",
                "admin": "GET /admin",
            },
        })
    return RedirectResponse(url="/admin/login")


@app.exception_handler(401)
async def unauthorized_handler(request: Request, exc):
    if request.url.path.startswith("/api/"):
        return JSONResponse({"detail": "Unauthorized"}, status_code=401)
    return RedirectResponse(url="/admin/login")
