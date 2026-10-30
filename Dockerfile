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

# Pre-warm: download the Chroma ONNX embedding model + verify the policy loads,
# so the first demo request never pays a cold-download pause.
RUN python -c "from agentshield.rag.store import RagStore; s=RagStore(collection='warmup'); print('corpus docs:', s.ingest())" \
 && python -c "from agentshield.engine_factory import AgentShield; s=AgentShield(); print('policy tools:', sorted(s.policy.tools))"

RUN useradd -m appuser && chown -R appuser /app /tmp/hf-cache
USER appuser

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health').status==200 else 1)"
CMD ["sh", "-c", "uvicorn agentshield.gateway.app:app --host 0.0.0.0 --port ${PORT:-8000}"]
