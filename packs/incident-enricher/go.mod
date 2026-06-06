module github.com/cordum-io/cordum-packs/packs/incident-enricher

go 1.25.10

require (
	github.com/cordum-io/cap/v2 v2.13.3
	github.com/cordum/cordum/sdk v0.2.0
	github.com/nats-io/nats.go v1.52.0
	github.com/redis/go-redis/v9 v9.20.0
	google.golang.org/protobuf v1.36.11
)

require (
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/klauspost/compress v1.18.5 // indirect
	github.com/nats-io/nkeys v0.4.15 // indirect
	github.com/nats-io/nuid v1.0.1 // indirect
	go.uber.org/atomic v1.11.0 // indirect
	golang.org/x/crypto v0.49.0 // indirect
	golang.org/x/net v0.51.0 // indirect
	golang.org/x/sys v0.42.0 // indirect
	golang.org/x/text v0.35.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20251202230838-ff82c1b0f217 // indirect
	google.golang.org/grpc v1.79.3 // indirect
)

replace github.com/cordum/cordum/sdk => ../../sdk
