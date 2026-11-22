FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    KAZNA_HOME=/data

WORKDIR /app
COPY pyproject.toml ./
COPY kazna ./kazna
RUN pip install --no-cache-dir -e ".[test]"

ENTRYPOINT ["kazna"]
