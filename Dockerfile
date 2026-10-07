FROM python:3.12-slim

WORKDIR /app

# Copy source first — pip install . needs the app/ package present to build the wheel.
COPY pyproject.toml .
COPY app/ app/
COPY static/ static/

# Install production dependencies only (no [dev] extras).
# lxml ships pre-built wheels for linux/amd64, so gcc is not required.
RUN pip install --no-cache-dir .

# Run as a dedicated non-root user.
RUN adduser --disabled-password --gecos "" --no-create-home appuser \
 && chown -R appuser:appuser /app
USER appuser

EXPOSE 8000

# Single worker — the in-memory store is not shareable across processes.
# Scale horizontally only after adding a shared store (e.g. Redis).
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
