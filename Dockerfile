FROM python:3.12-slim
ARG PKG_SPEC="mcpsafetywarden[all]"
RUN pip install --no-cache-dir --upgrade pip && \
    for i in $(seq 1 10); do \
        pip install --no-cache-dir "$PKG_SPEC" "litellm>=1.83.7" "protobuf>=5.29.6" && break; \
        [ "$i" = 10 ] && exit 1; \
        echo "install attempt $i failed, retrying in 30s"; sleep 30; \
    done
ENTRYPOINT ["mcpsafetywarden-server"]
