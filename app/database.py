import logging
from pathlib import Path

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.config import settings

logger = logging.getLogger(__name__)

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_DATA_DIR = _PROJECT_ROOT / "data"
_DATA_DIR.mkdir(exist_ok=True)

_db_url = settings.database_url
if _db_url.startswith("sqlite+aiosqlite:///./"):
    _db_url = f"sqlite+aiosqlite:///{_DATA_DIR / _db_url.split('///./data/')[1]}"

engine = create_async_engine(_db_url, echo=False)
async_session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


async def get_db() -> AsyncSession:
    async with async_session() as session:
        yield session


async def migrate_add_api_key() -> None:
    """Add api_key column to existing sites table if missing."""
    from app.models import generate_api_key

    async with engine.begin() as conn:
        result = await conn.execute(text("PRAGMA table_info(sites)"))
        columns = [row[1] for row in result.fetchall()]
        if "api_key" not in columns:
            logger.info("Migrating: adding api_key column to sites")
            await conn.execute(text("ALTER TABLE sites ADD COLUMN api_key VARCHAR(255) DEFAULT ''"))
            rows = await conn.execute(text("SELECT id FROM sites WHERE api_key = '' OR api_key IS NULL"))
            for row in rows.fetchall():
                key = generate_api_key()
                await conn.execute(text("UPDATE sites SET api_key = :key WHERE id = :id"), {"key": key, "id": row[0]})
            logger.info("Migration complete: api_key added to all sites")


async def migrate_add_dkim() -> None:
    """Add DKIM columns to the sites table and generate keys where missing."""
    from app.dkim_util import generate_dkim_keypair

    async with engine.begin() as conn:
        result = await conn.execute(text("PRAGMA table_info(sites)"))
        columns = [row[1] for row in result.fetchall()]
        if "dkim_selector" not in columns:
            logger.info("Migrating: adding dkim_selector column to sites")
            await conn.execute(text("ALTER TABLE sites ADD COLUMN dkim_selector VARCHAR(63) DEFAULT 'smtp'"))
        if "dkim_private_key" not in columns:
            logger.info("Migrating: adding dkim_private_key column to sites")
            await conn.execute(text("ALTER TABLE sites ADD COLUMN dkim_private_key TEXT DEFAULT ''"))

        rows = await conn.execute(
            text("SELECT id FROM sites WHERE dkim_private_key = '' OR dkim_private_key IS NULL")
        )
        for row in rows.fetchall():
            private_pem, _ = generate_dkim_keypair()
            await conn.execute(
                text("UPDATE sites SET dkim_private_key = :pem, dkim_selector = 'smtp' WHERE id = :id"),
                {"pem": private_pem, "id": row[0]},
            )
        logger.info("Migration complete: DKIM keys ensured for all sites")


async def seed_admin_user() -> None:
    """Create the first admin user from env vars if no users exist yet.

    Refuses to seed when ADMIN_PASSWORD is empty. This used to hash the empty
    string and store it, producing an admin whose password was "" — accepted by
    the SMTP AUTH path, which grants unrestricted relay. Failing startup is the
    right trade: a deployment with no admin password is unusable anyway, and a
    loud error beats a silently open relay.
    """
    from app.models import User, hash_password

    async with async_session() as session:
        result = await session.execute(text("SELECT COUNT(*) FROM users"))
        count = result.scalar()
        if count == 0:
            if not settings.admin_password:
                raise RuntimeError(
                    "ADMIN_PASSWORD is empty and no users exist yet, so the first admin "
                    "cannot be created securely. Set ADMIN_PASSWORD in .env (or run "
                    "setup.sh, which prompts for one) and start the service again."
                )
            pw_hash, pw_salt = hash_password(settings.admin_password)
            admin = User(
                username=settings.admin_username,
                password_hash=pw_hash,
                password_salt=pw_salt,
                role="admin",
            )
            session.add(admin)
            await session.commit()
            logger.info("Created admin user: %s", settings.admin_username)


async def migrate_hardening() -> None:
    """Versioned additive migration for the supported SQLite single-instance mode.

    Canonical collisions abort startup rather than silently merging tenants.
    Backup using tools/backup.py before upgrading an existing database.
    """
    from app.domain_util import normalize_domain
    from app.secret_store import decrypt, encrypt
    if engine.dialect.name != 'sqlite':
        raise RuntimeError('Only SQLite is supported; PostgreSQL requires a separate migration plan')
    additions = {
        'users': {'smtp_domains': "TEXT NOT NULL DEFAULT ''"},
        'email_logs': {'message_id': "VARCHAR(255) NOT NULL DEFAULT ''",
                       'relay_source': "VARCHAR(255) NOT NULL DEFAULT ''",
                       'attempts': 'INTEGER NOT NULL DEFAULT 0',
                       'raw_message': "TEXT NOT NULL DEFAULT ''"},
    }
    async with engine.begin() as conn:
        await conn.execute(text('CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY)'))
        for table, fields in additions.items():
            columns = {row[1] for row in (await conn.execute(text(f'PRAGMA table_info({table})'))).fetchall()}
            for name, declaration in fields.items():
                if name not in columns:
                    await conn.execute(text(f'ALTER TABLE {table} ADD COLUMN {name} {declaration}'))
        rows = (await conn.execute(text('SELECT id, domain FROM sites'))).fetchall()
        canonical = [(id_, normalize_domain(domain)) for id_, domain in rows]
        if len({domain for _, domain in canonical}) != len(canonical):
            raise RuntimeError('Normalized domain collision. Resolve duplicate sites before upgrading.')
        for id_, domain in canonical:
            await conn.execute(text('UPDATE sites SET domain=:domain WHERE id=:id'), {'id': id_, 'domain': domain})
        for table, fields in {'sites': ['relay_password', 'dkim_private_key'], 'email_providers': ['password'],
                             'outbox_messages': ['payload'], 'email_logs': ['raw_message']}.items():
            for name in fields:
                for row in (await conn.execute(text(f'SELECT id, {name} FROM {table}'))).fetchall():
                    # Re-encrypt with primary key, enabling gradual key rotation.
                    if row[1]:
                        await conn.execute(text(f'UPDATE {table} SET {name}=:value WHERE id=:id'),
                                           {'id': row[0], 'value': encrypt(decrypt(row[1]))})
        await conn.execute(text("UPDATE email_logs SET status='accepted' WHERE status='sent'"))
        await conn.execute(text("UPDATE email_logs SET status='failed' WHERE status='error'"))
        await conn.execute(text('INSERT OR IGNORE INTO schema_migrations(version) VALUES(1)'))
