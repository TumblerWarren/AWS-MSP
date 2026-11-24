# Multi-stage Dockerfile for deploying the MSP Platform + Agents to AWS
# Compatible with both AWS ECS Fargate (UI + API + Agents on :8080) and
# Amazon Bedrock AgentCore Runtime (/ping and /invocations on :8080).

FROM node:22-alpine AS frontend-builder
WORKDIR /build/frontend
COPY frontend/package*.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

FROM python:3.12-slim AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_SYSTEM_PYTHON=1 \
    PORT=8080

RUN apt-get update && apt-get install -y --no-install-recommends \
      git \
      curl \
      unzip \
      ca-certificates \
    && curl -fsSL https://releases.hashicorp.com/terraform/1.10.5/terraform_1.10.5_linux_amd64.zip -o /tmp/tf.zip \
    && unzip /tmp/tf.zip -d /usr/local/bin \
    && rm -f /tmp/tf.zip \
    && rm -rf /var/lib/apt/lists/*

# Install uv & uvx (used by Strands MCPClient to launch official AWS Labs MCP servers)
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /usr/local/bin/

WORKDIR /app
COPY packages/msp_policy /app/packages/msp_policy
COPY backend /app/backend
COPY --from=frontend-builder /build/frontend/dist /app/frontend/dist

WORKDIR /app/backend
RUN uv pip install --system /app/packages/msp_policy . \
    && uv tool install awslabs.aws-api-mcp-server \
    && uv tool install awslabs.cloudtrail-mcp-server

EXPOSE 8080
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
