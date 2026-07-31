# Sentinel RAG AI engine.
#
# The heavy part of this image is sentence-transformers, which drags in torch.
# Installing the CPU-only torch wheel first cuts the image from roughly 6 GB to
# 1.5 GB: the default wheel bundles CUDA libraries that are pure ballast on a
# home server with no GPU.

FROM python:3.12-slim AS build

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /build

# CPU-only torch, ahead of everything that would otherwise pull the CUDA build.
RUN pip install --prefix=/install --extra-index-url https://download.pytorch.org/whl/cpu torch

COPY requirements.txt ./
RUN pip install --prefix=/install -r requirements.txt

# ---- runtime -------------------------------------------------------------
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    # Keep the model cache on the mounted volume so a container rebuild does not
    # re-download 2.2 GB of weights.
    HF_HOME=/data/models \
    SENTINEL_DATA_DIR=/data \
    SENTINEL_EVENTS_PATH=/data/events.jsonl \
    SENTINEL_ADVISORY_DIR=/app/data/advisories \
    SENTINEL_CHROMA_DIR=/data/chroma \
    SENTINEL_INDEX_DIR=/data/index \
    SENTINEL_AUDIT_LOG=/data/audit.log \
    SENTINEL_API_HOST=0.0.0.0

COPY --from=build /install /usr/local

WORKDIR /app
COPY sentinel/ ./sentinel/
COPY pyproject.toml ./

# Non-root. The engine never needs privileges — the one privileged operation in
# the system (ufw) is deliberately not available inside this container, so an
# RCE in the Python layer cannot reach the host firewall. See the compose file
# for how active response is wired instead.
RUN useradd --system --uid 65532 --create-home --home-dir /home/sentinel sentinel \
    && mkdir -p /data \
    && chown -R sentinel:sentinel /data /app

USER sentinel

EXPOSE 8000

# A liveness probe that deliberately hits /api/health, which does not load the
# embedding model — a probe that triggered a 2 GB model load would kill the
# container it was meant to protect.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=4).status==200 else 1)"

CMD ["python", "-m", "sentinel", "serve", "--host", "0.0.0.0", "--port", "8000"]
