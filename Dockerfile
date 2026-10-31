# Kill Chain - proper project (frontend + backend, no demo data)
FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY engine/ ./engine/
COPY rules/ ./rules/
COPY frontend/ ./frontend/
COPY main.py .
EXPOSE 8001
CMD ["python", "main.py", "serve", "--db", "out.duckdb", "--port", "8001", "--host", "0.0.0.0"]
