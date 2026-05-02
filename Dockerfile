FROM python:3.12-slim
ARG PKG_SPEC="mcpsafetywarden[all]"
RUN pip install --no-cache-dir "$PKG_SPEC"
ENTRYPOINT ["mcpsafetywarden-server"]
