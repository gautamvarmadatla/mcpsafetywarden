FROM python:3.12-slim

RUN pip install --no-cache-dir "mcpsafetywarden[all]==1.2.1"

ENTRYPOINT ["mcpsafetywarden-server"]
