from unittest.mock import patch

from app.config import Settings, settings


def test_web_port_defaults_to_3005(monkeypatch):
    monkeypatch.delenv("WEB_PORT", raising=False)
    assert Settings(_env_file=None).web_port == 3005


def test_web_port_environment_override(monkeypatch):
    monkeypatch.setenv("WEB_PORT", "3010")
    assert Settings(_env_file=None).web_port == 3010


def test_launcher_uses_configured_port(monkeypatch):
    from app.__main__ import main

    monkeypatch.setattr(settings, "web_port", 3005)
    monkeypatch.setattr(settings, "web_host", "127.0.0.1")
    with patch("app.__main__.uvicorn.run") as run:
        main()
    run.assert_called_once_with("app.main:app", host="127.0.0.1", port=3005, workers=1, forwarded_allow_ips="127.0.0.1")


def test_container_and_installer_use_same_port(repo_root):
    docker = (repo_root / "Dockerfile").read_text()
    compose = (repo_root / "docker-compose.yml").read_text()
    setup = (repo_root / "setup.sh").read_text()
    assert "WEB_PORT=3005" in docker
    assert '"python", "-m", "app"' in docker
    assert "127.0.0.1:${WEB_PORT:-3005}:${WEB_PORT:-3005}" in compose
    assert "WEB_PORT=$PORT" in setup
    assert 'PORT="${PORT:-3005}"' in setup
    assert ":8000" not in compose
