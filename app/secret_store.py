"""Encrypted-at-rest columns. Key is external to SQLite; never use session key."""

from pathlib import Path

from cryptography.fernet import Fernet, MultiFernet
from sqlalchemy.types import Text, TypeDecorator

from app.config import settings


def cipher():
    keys = [k.strip() for k in settings.data_encryption_keys.split(",") if k.strip()]
    if not keys:
        path = Path(__file__).resolve().parent.parent / "data" / ".encryption_key"
        path.parent.mkdir(mode=0o700, exist_ok=True)
        if not path.exists():
            try:
                with path.open("x") as f:
                    f.write(Fernet.generate_key().decode())
                path.chmod(0o600)
            except FileExistsError:
                pass
        keys = [path.read_text().strip()]
    return MultiFernet([Fernet(key.encode()) for key in keys])


def encrypt(value):
    if not value or value.startswith("enc:v1:"):
        return value
    return "enc:v1:" + cipher().encrypt(value.encode()).decode()


def decrypt(value):
    if value and value.startswith("enc:v1:"):
        return cipher().decrypt(value[7:].encode()).decode()
    return value  # old databases are converted at startup


class SecretText(TypeDecorator):
    impl = Text
    cache_ok = True

    def process_bind_param(self, value, dialect):
        return encrypt(value)

    def process_result_value(self, value, dialect):
        return decrypt(value)
