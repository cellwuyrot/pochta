FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Install dependencies in their own layer so that editing source does not force a
# full reinstall. app/__init__.py comes along because pyproject reads the version
# from it (dynamic metadata) and declares packages = ["app"] — without it the
# build backend has nothing to resolve.
COPY pyproject.toml ./
COPY app/__init__.py ./app/__init__.py
RUN pip install --no-cache-dir .

# The real source overlays the installed copy; WORKDIR is /app, so `uvicorn
# app.main:app` imports from here.
COPY . .

RUN mkdir -p data app/static

# Run as an unprivileged user instead of root.
RUN useradd --create-home --uid 10001 appuser \
    && chown -R appuser:appuser /app
USER appuser

ENV WEB_HOST=0.0.0.0 WEB_PORT=3005

EXPOSE 3005 2525

CMD ["python", "-m", "app"]
