FROM python:3.12-slim
ARG PKG_SPEC="mcpsafetywarden[all]"
RUN apt-get update && apt-get upgrade -y --no-install-recommends && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir --upgrade pip "setuptools>=83.0.0" && \
    for i in $(seq 1 10); do \
        pip install --no-cache-dir "$PKG_SPEC" "litellm>=1.83.7" "protobuf>=5.29.6" "setuptools>=83.0.0" && break; \
        [ "$i" = 10 ] && exit 1; \
        echo "install attempt $i failed, retrying in 30s"; sleep 30; \
    done
ENTRYPOINT ["mcpsafetywarden-server"]
