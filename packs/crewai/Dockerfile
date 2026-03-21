# Stage 1: Build Go worker
FROM golang:1.24 AS go-builder

WORKDIR /build
COPY go.mod go.sum ./
COPY ../../sdk /sdk
RUN go mod download

COPY cmd/ cmd/
COPY internal/ internal/
RUN CGO_ENABLED=0 go build -o /out/cordum-crewai ./cmd/cordum-crewai/

# Stage 2: Python runtime + Go binary
FROM python:3.12-slim

WORKDIR /app

COPY sidecar/requirements.txt /app/sidecar/requirements.txt
RUN pip install --no-cache-dir -r /app/sidecar/requirements.txt

COPY ../../integrations/agent-adapters /app/agent-adapters
RUN pip install --no-cache-dir -e /app/agent-adapters

COPY sidecar/ /app/sidecar/
COPY --from=go-builder /out/cordum-crewai /app/cordum-crewai

ENV PYTHONPATH="/app/sidecar:/app/agent-adapters"
ENV PYTHONUNBUFFERED=1
ENV CORDUM_CREWAI_SIDECAR_COMMAND="python"
ENV CORDUM_CREWAI_SIDECAR_ARGS="-m,cordum_crewai_sidecar"

ENTRYPOINT ["/app/cordum-crewai"]
