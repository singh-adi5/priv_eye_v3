FROM python:3.11-slim

WORKDIR /app

# Install deps first so layer is cached across code changes
COPY pyproject.toml ./
RUN pip install --no-cache-dir -e ".[insights]"

COPY priveye_api/ ./priveye_api/

EXPOSE 8000

CMD ["uvicorn", "priveye_api.main:app", "--host", "0.0.0.0", "--port", "8000"]
