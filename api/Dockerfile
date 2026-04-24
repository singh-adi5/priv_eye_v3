FROM python:3.11-slim

WORKDIR /app

# Copy source first — non-editable install requires package source to be present.
# Editable install (-e) before COPY causes the Docker build to fail.
COPY pyproject.toml ./
COPY priveye_api/ ./priveye_api/

RUN pip install --no-cache-dir ".[insights]"

EXPOSE 8000

CMD ["uvicorn", "priveye_api.main:app", "--host", "0.0.0.0", "--port", "8000"]
