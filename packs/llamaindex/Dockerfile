FROM golang:1.24 AS go-builder
WORKDIR /build
COPY go.mod go.sum ./
COPY ../../sdk /sdk
COPY ../../integrations/sidecar-template/go /sidecar-template
RUN go mod download
COPY cmd/ cmd/
COPY internal/ internal/
RUN CGO_ENABLED=0 go build -o /out/cordum-llamaindex ./cmd/cordum-llamaindex/

FROM python:3.12-slim
WORKDIR /app
COPY sidecar/requirements.txt /app/sidecar/requirements.txt
RUN pip install --no-cache-dir -r /app/sidecar/requirements.txt
COPY ../../integrations/sidecar-template/python /app/sidecar-template
COPY sidecar/ /app/sidecar/
COPY --from=go-builder /out/cordum-llamaindex /app/cordum-llamaindex
ENV PYTHONPATH="/app/sidecar:/app/sidecar-template"
ENV CORDUM_LLAMAINDEX_PYTHON_CMD="python"
ENV CORDUM_LLAMAINDEX_SIDECAR_MODULE="cordum_llamaindex_sidecar"
EXPOSE 8080
ENTRYPOINT ["/app/cordum-llamaindex"]
