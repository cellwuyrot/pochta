"""SMTP service with an admin panel.

``__version__`` is the single source of truth: pyproject.toml reads it via
setuptools' dynamic-version hook, and both the FastAPI app and /api/health
report it. Previously the version was written out in three places and two of
them disagreed.
"""

__version__ = "2.1.0"
