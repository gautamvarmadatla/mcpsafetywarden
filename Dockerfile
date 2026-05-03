FROM python:3.12-slim
ARG PKG_SPEC="mcpsafetywarden[all]"
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir "$PKG_SPEC" "litellm>=1.83.7" "protobuf>=5.29.6"
ENTRYPOINT ["mcpsafetywarden-server"]
