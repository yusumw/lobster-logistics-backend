FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY server.py .

ENV DB_PATH=/data/lobster.db

RUN mkdir -p /data

# 使用 shell form 讓 $PORT 被正確展開（Railway 會注入 PORT 環境變量）
CMD gunicorn server:app --bind 0.0.0.0:${PORT:-8080} --workers 2 --timeout 120
