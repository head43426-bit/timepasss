# ASK — Analyse Secure Kill (frontend + Python/DuckDB/NetworkX backend)
# Built by docker-compose.yml. The old Dockerfile was incomplete: it
# omitted showcase.html, data/ (MITRE index), assets/ (logo/favicons)
# and the sample/log generator, so / and /assets/* broke in Docker
# even though they worked locally. All of those are copied here now.
# The database itself is NOT in the image — docker-compose.yml mounts
# the ask_data volume at /app/db for it.
FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY engine/ ./engine/
COPY rules/ ./rules/
COPY frontend/ ./frontend/
COPY data/ ./data/
COPY assets/ ./assets/
COPY main.py showcase.html generate_logs.py sample_attack.log ./
RUN mkdir -p /app/db
EXPOSE 8001
CMD ["python", "main.py", "serve", "--db", "/app/db/out.duckdb", "--port", "8001", "--host", "0.0.0.0"]
