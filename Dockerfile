FROM python:3.11-slim AS builder

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

RUN pip install --no-cache-dir --upgrade pip && \
    pip wheel --no-cache-dir --wheel-dir /wheels -r requirements.txt

FROM python:3.11-slim

WORKDIR /app

COPY --from=builder /wheels /wheels

RUN pip install --no-cache-dir --no-index --find-links=/wheels /wheels/* && \
    rm -rf /wheels && \
    apt-get update && apt-get install -y --no-install-recommends gosu && \
    apt-get purge -y --auto-remove && \
    rm -rf /var/lib/apt/lists/*

COPY main.py ./
COPY config.py ./
COPY database.py ./
COPY db_models.py ./
COPY custom_types/ ./custom_types/
COPY middleware/ ./middleware/
COPY models/ ./models/
COPY routers/ ./routers/
COPY services/ ./services/

COPY entrypoint.sh /entrypoint.sh

RUN chmod +x /entrypoint.sh && \
    useradd -m -u 1000 appuser && \
    chown -R appuser:appuser /app

USER appuser

EXPOSE 4323

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:4323/health').read()"

ENTRYPOINT ["/entrypoint.sh"]
CMD ["python", "-u", "main.py"]
