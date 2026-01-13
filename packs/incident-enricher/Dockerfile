FROM golang:1.23 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG SERVICE
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/worker ./cmd/${SERVICE}

FROM gcr.io/distroless/base-debian12
COPY --from=build /out/worker /worker
ENTRYPOINT ["/worker"]
