PACK_ID := incident-enricher
VERSION ?= 0.1.0
BIN_DIR := bin

.PHONY: build bundle install clean

build:
	@mkdir -p $(BIN_DIR)
	go build -o $(BIN_DIR)/fetcher ./cmd/fetcher
	go build -o $(BIN_DIR)/summarizer ./cmd/summarizer
	go build -o $(BIN_DIR)/poster ./cmd/poster
	go build -o $(BIN_DIR)/ingester ./cmd/ingester

bundle:
	./scripts/bundle.sh

install:
	./scripts/install.sh

clean:
	rm -rf $(BIN_DIR) dist
