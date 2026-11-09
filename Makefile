APP_NAME := ports-tui
BIN_DIR := bin
CMD_PATH := ./cmd/ports-tui

.PHONY: all build test fmt vet run demo clean

all: build

build:
	@mkdir -p $(BIN_DIR)
	go build -o $(BIN_DIR)/$(APP_NAME) $(CMD_PATH)
	@echo "Build complete: $(BIN_DIR)/$(APP_NAME)"

test:
	go test -race -count=1 ./...

fmt:
	gofmt -l -w .

vet:
	go vet ./...

run:
	./$(BIN_DIR)/$(APP_NAME)

demo: build
	./$(BIN_DIR)/$(APP_NAME) serve --demo

clean:
	rm -rf $(BIN_DIR)
