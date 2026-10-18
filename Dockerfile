FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    RUSSDESK_DATA_DIR=/data \
    RUSSDESK_PORT=21114

WORKDIR /app
COPY russdesk ./russdesk
RUN useradd --system --uid 10001 russdesk && mkdir -p /data && chown russdesk /data
USER russdesk

VOLUME /data
EXPOSE 21114
HEALTHCHECK --interval=30s --timeout=5s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:21114/api/login-options', timeout=3)"
CMD ["python", "-m", "russdesk"]
