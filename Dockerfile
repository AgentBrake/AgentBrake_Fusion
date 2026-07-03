FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV AGENTBRAKE_HOST=0.0.0.0
ENV AGENTBRAKE_BACKEND_PORT=8765
ENV AGENTBRAKE_DEMO_MODE=true
ENV AGENTBRAKE_SANDBOX=true
ENV ALLOW_REAL_TOOLS=false

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    nodejs \
    npm \
  && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.zh-CN.md README.md ./
COPY backend/requirements.txt backend/requirements.txt
COPY src src
COPY web/studio web/studio
COPY configs configs
COPY data data
COPY scripts scripts

RUN python -m pip install --no-cache-dir --upgrade pip \
  && python -m pip install --no-cache-dir -r backend/requirements.txt \
  && python -m pip install --no-cache-dir -e ".[test]" \
  && cd web/studio && npm ci && npm run build

EXPOSE 8765

CMD ["python", "-m", "agentbrake.cli", "studio-server", "--repo", ".", "--host", "0.0.0.0", "--port", "8765", "--demo-mode"]
