FROM golang:1.25 AS build
WORKDIR /src
COPY packs/incident-enricher/go.mod packs/incident-enricher/go.sum ./
COPY sdk /sdk
RUN go mod download
COPY packs/incident-enricher/ .
ARG SERVICE
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/worker ./cmd/${SERVICE}

FROM gcr.io/distroless/base-debian12
COPY --from=build /out/worker /worker
ENTRYPOINT ["/worker"]
