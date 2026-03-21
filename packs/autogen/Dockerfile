FROM golang:1.24 AS go-builder
WORKDIR /build
COPY go.mod go.sum ./
COPY ../../sdk /sdk
COPY ../../integrations/sidecar-template/go /sidecar-template
RUN go mod download
COPY cmd/ cmd/
COPY internal/ internal/
RUN CGO_ENABLED=0 go build -o /out/cordum-autogen ./cmd/cordum-autogen/

FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends docker.io && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY sidecar/requirements.txt /app/sidecar/requirements.txt
RUN pip install --no-cache-dir -r /app/sidecar/requirements.txt
COPY ../../integrations/sidecar-template/python /app/sidecar-template
COPY ../../integrations/agent-adapters /app/agent-adapters
RUN pip install --no-cache-dir -e /app/agent-adapters
COPY sidecar/ /app/sidecar/
COPY --from=go-builder /out/cordum-autogen /app/cordum-autogen
ENV PYTHONPATH="/app/sidecar:/app/sidecar-template:/app/agent-adapters"
ENV CORDUM_AUTOGEN_PYTHON_CMD="python"
ENV CORDUM_AUTOGEN_SIDECAR_MODULE="cordum_autogen_sidecar"
ENV CORDUM_AUTOGEN_CODE_EXECUTION="docker"
EXPOSE 8080
ENTRYPOINT ["/app/cordum-autogen"]
