# One image, two entrypoints: the scan job (default) and the read-only dashboard
# (Cloud Run service overrides the command with gunicorn).
FROM openpolicyagent/opa:1.21.0-static AS opa

FROM python:3.13-slim
ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 PYTHONPATH=/srv/app POLICY_DIR=/srv/policies
WORKDIR /srv
COPY --from=opa /opa /usr/local/bin/opa
COPY app/requirements.txt app/requirements.txt
RUN pip install -r app/requirements.txt
COPY policies policies
COPY app/scanner app/scanner
COPY app/ui app/ui
RUN useradd -r -u 10001 app
USER 10001
ENTRYPOINT ["python", "-m", "scanner.main"]
