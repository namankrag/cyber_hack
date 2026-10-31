# AgentShield demo image: FastAPI gateway + local RAG (no API keys needed).
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    HF_HOME=/tmp/hf-cache

WORKDIR /app
# requirements.txt is the declared source; requirements.lock is the
# pip-compile'd, hash-pinned build input (audit M9). Re-lock with:
#   pip-compile --generate-hashes requirements.txt -o requirements.lock
COPY requirements.lock .
RUN pip install --no-cache-dir --require-hashes -r requirements.lock
COPY . .
# Build-time evidence manifest (B6): records commit/date/test counts for
# the console evidence page. The gateway never shells out to git at request
# time, so the image stamps its own provenance here (CI passes GITHUB_SHA;
# Render can pass RENDER_GIT_COMMIT as a build arg; pass PYTEST_COUNT to
# record the suite count instead of "not recorded").
ARG BUILD_COMMIT=""
ARG RENDER_GIT_COMMIT=""
ARG GITHUB_SHA=""
ARG PYTEST_COUNT=""
RUN if [ -n "$PYTEST_COUNT" ]; then python scripts/write_build_info.py --pytest-count "$PYTEST_COUNT"; else python scripts/write_build_info.py; fi \
 && python -c "from agentshield.gateway.evidence import build_info; print(build_info())"

# Pre-warm: verify the RAG corpus ingests (offline embedding by default, no
# model download) and the policy loads, so the first demo request is instant.
# Set AGENTSHIELD_RAG_EMBEDDING=onnx to use Chroma's model-based embedding.
RUN python -c "from agentshield.rag.store import RagStore; s=RagStore(collection='warmup'); print('corpus docs:', s.ingest())" \
 && python -c "from agentshield.engine_factory import AgentShield; s=AgentShield(); print('policy tools:', sorted(s.policy.tools))"

RUN useradd -m appuser && chown -R appuser /app /tmp/hf-cache
USER appuser

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health').status==200 else 1)"
# AGENTSHIELD_BIND_HOST: set to "::" on hosts whose private network is
# IPv6-only (older Railway environments) so sibling services can reach it.
# The entrypoint auto-generates AGENTSHIELD_HARNESS_SECRET if unset, so the
# trust/provenance demo works out of the box (set it explicitly to persist).
CMD ["sh", "/app/scripts/entrypoint.sh"]
