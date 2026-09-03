FROM python:3.12-slim

WORKDIR /app

COPY pyproject.toml ./
COPY src ./src

RUN pip install --no-cache-dir .

ENV PYTHONPATH=/app/src
EXPOSE 8080

CMD ["uvicorn", "mira_protect.app:app", "--host", "0.0.0.0", "--port", "8080"]
