FROM python:3.11-slim

WORKDIR /app
COPY . /app
RUN pip install --no-cache-dir -e .

ENV AXIOM_AUDIT_LOG_PATH=/var/log/axiom/audit.log
RUN mkdir -p /var/log/axiom

CMD ["python", "-m", "securado_axiom.gateway.src.app"]
