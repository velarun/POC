# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
BINARY_NAME=proxyserver
BINARY_UNIX=$(BINARY_NAME)_unix

all: go

go: go/build

go/build:
	@echo "Building $(BIN_NAME)"
	@go version
	$(GOBUILD) -o $(BINARY_NAME)
	@chmod 777 $(BINARY_NAME)

clean: 
	$(GOCLEAN)
	rm -f $(BINARY_NAME)
	rm -f $(BINARY_UNIX)

# Cross compilation
build-linux:
		CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GOBUILD) -o $(BINARY_UNIX) -v

