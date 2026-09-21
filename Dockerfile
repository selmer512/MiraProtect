FROM python:3.12-slim

WORKDIR /app

COPY pyproject.toml ./
COPY src ./src

RUN pip install --no-cache-dir .

ENV PYTHONPATH=/app/src
ENV MIRA_BIND_HOST=0.0.0.0
ENV MIRA_BIND_PORT=8080
EXPOSE 8080

CMD ["mira-protect-server"]
