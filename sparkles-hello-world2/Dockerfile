FROM python:3.12-slim

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends cron \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .
COPY templates ./templates
COPY scripts ./scripts
COPY crontab /etc/cron.d/url-monitor

RUN chmod 0644 /etc/cron.d/url-monitor \
    && chmod +x /app/scripts/check_urls.sh \
    && mkdir -p /app/data \
    && touch /var/log/cron.log

EXPOSE 8000

CMD ["sh", "-c", "cron && exec python app.py"]
