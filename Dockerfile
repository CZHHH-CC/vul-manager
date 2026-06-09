# ─────────────────────────────────────────────────────────────
# Stage 1: compile Tailwind CSS to a static stylesheet
#   Uses the official standalone CLI (no Node toolchain needed).
# ─────────────────────────────────────────────────────────────
FROM debian:bookworm-slim AS cssbuild

ARG TAILWIND_VERSION=v3.4.16
WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Only the inputs needed to compile CSS (maximises layer caching)
COPY tailwind.config.js ./
COPY static/css/tailwind-input.css ./static/css/tailwind-input.css
COPY templates ./templates

RUN curl -sL "https://github.com/tailwindlabs/tailwindcss/releases/download/${TAILWIND_VERSION}/tailwindcss-linux-x64" \
        -o /usr/local/bin/tailwindcss \
    && chmod +x /usr/local/bin/tailwindcss \
    && tailwindcss -c tailwind.config.js \
        -i static/css/tailwind-input.css \
        -o static/css/app.css --minify

# ─────────────────────────────────────────────────────────────
# Stage 2: application image
# ─────────────────────────────────────────────────────────────
FROM python:3.12-slim

WORKDIR /app

# System dependencies for psycopg2 and lxml
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq-dev \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Python dependencies (layer-cached on requirements.txt)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Application code
COPY . .

# Compiled CSS from the build stage (overwrites any stale committed copy)
COPY --from=cssbuild /build/static/css/app.css ./static/css/app.css

# Runtime directories
RUN mkdir -p /app/uploads /app/reports/templates

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import httpx; httpx.get('http://localhost:8000/api/dashboard/stats').raise_for_status()" || exit 1

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
