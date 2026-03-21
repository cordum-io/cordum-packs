# Stage 1: Build Go worker
FROM golang:1.24 AS go-builder

WORKDIR /build
COPY go.mod go.sum ./
COPY ../../sdk /sdk
COPY ../../integrations/sidecar-template/go /sidecar-template
RUN go mod download

COPY cmd/ cmd/
COPY internal/ internal/
RUN CGO_ENABLED=0 go build -o /out/cordum-langchain ./cmd/cordum-langchain/

# Stage 2: Python runtime + Go binary
FROM python:3.12-slim

WORKDIR /app

# Install Python dependencies
COPY sidecar/requirements.txt /app/sidecar/requirements.txt
RUN pip install --no-cache-dir -r /app/sidecar/requirements.txt

# Install shared sidecar template + agent adapters
COPY ../../integrations/sidecar-template/python /app/sidecar-template
COPY ../../integrations/agent-adapters /app/agent-adapters
RUN pip install --no-cache-dir -e /app/agent-adapters

# Copy sidecar code
COPY sidecar/ /app/sidecar/

# Copy Go binary
COPY --from=go-builder /out/cordum-langchain /app/cordum-langchain

# Add Python paths
ENV PYTHONPATH="/app/sidecar:/app/sidecar-template:/app/agent-adapters"
ENV CORDUM_LANGCHAIN_PYTHON_CMD="python"
ENV CORDUM_LANGCHAIN_SIDECAR_MODULE="cordum_langchain_sidecar"

EXPOSE 8080

ENTRYPOINT ["/app/cordum-langchain"]
