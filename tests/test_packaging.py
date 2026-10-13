"""Packaging and version consistency.

These exist because the project shipped for a while with the version written out
in three places (two of which disagreed: pyproject said 1.0.0 while the app and
/api/health both said 2.0.0), and with no ``[build-system]`` table at all — so
``pip install .`` failed on any checkout where the app had run once and created
``data/``.
"""
import tomllib

import pytest
from fastapi.testclient import TestClient

import app as app_package


@pytest.fixture
def pyproject(repo_root):
    with open(repo_root / "pyproject.toml", "rb") as handle:
        return tomllib.load(handle)


def test_build_system_is_declared(pyproject):
    """Without this table, pip falls back to a legacy setuptools shim."""
    assert "build-system" in pyproject
    assert pyproject["build-system"]["build-backend"] == "setuptools.build_meta"


def test_packages_are_listed_explicitly(pyproject):
    """Flat-layout auto-discovery breaks once the runtime data/ directory exists."""
    packages = pyproject["tool"]["setuptools"]["packages"]
    assert packages == ["app"], (
        "packages must be explicit: setuptools' auto-discovery aborts with "
        "'Multiple top-level packages discovered: [app, data]' because data/ is "
        "created at runtime"
    )


def test_templates_ship_as_package_data(pyproject):
    """Jinja templates are loaded from inside the package at runtime."""
    package_data = pyproject["tool"]["setuptools"]["package-data"]["app"]
    assert any("templates" in pattern for pattern in package_data)


def test_version_is_sourced_from_the_package(pyproject):
    assert pyproject["project"]["dynamic"] == ["version"]
    assert pyproject["tool"]["setuptools"]["dynamic"]["version"] == {"attr": "app.__version__"}
    assert "version" not in pyproject["project"], "a static version would shadow the dynamic one"


def test_health_endpoint_reports_the_package_version():
    from app.config import settings

    settings.smtp_port = 0
    from app.main import app

    # Plain TestClient, not a context manager: entering the context runs the
    # lifespan, which starts the real SMTP controller. /api/health needs neither.
    client = TestClient(app)
    payload = client.get("/api/health").json()
    assert payload["version"] == app_package.__version__


def test_fastapi_app_reports_the_package_version():
    from app.config import settings

    settings.smtp_port = 0
    from app.main import app

    assert app.version == app_package.__version__


def test_dockerfile_copies_the_version_file_before_installing(repo_root):
    """The dependency-cache layer installs before the source copy, and the
    dynamic version needs app/__init__.py to exist at that point."""
    dockerfile = (repo_root / "Dockerfile").read_text(encoding="utf-8")
    install_at = dockerfile.index("pip install")
    init_copy_at = dockerfile.index("app/__init__.py")
    assert init_copy_at < install_at, (
        "app/__init__.py must be COPYed before `pip install .`, otherwise the "
        "dynamic version cannot be resolved and the build fails"
    )


def test_dockerignore_excludes_runtime_secrets(repo_root):
    """data/ holds the SQLite DB and data/.secret_key; .gitignore does not apply
    to Docker builds, so it has to be repeated here."""
    ignored = {
        line.strip()
        for line in (repo_root / ".dockerignore").read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    }
    for entry in ("data/", ".git", ".env"):
        assert entry in ignored, f"{entry} must be excluded from the Docker build context"
