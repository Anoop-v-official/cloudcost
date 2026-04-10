APP_NAME := cloudcost
BUILD_DIR := dist
MAIN := cmd/cli/main.go

.PHONY: build run clean install test

# Build for current platform
build:
	@echo "🔨 Building $(APP_NAME)..."
	@mkdir -p $(BUILD_DIR)
	go build -o $(BUILD_DIR)/$(APP_NAME) $(MAIN)
	@echo "✅ Built: $(BUILD_DIR)/$(APP_NAME)"

# Build for all platforms
build-all:
	@echo "🔨 Building for all platforms..."
	@mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=amd64 go build -o $(BUILD_DIR)/$(APP_NAME)-linux-amd64 $(MAIN)
	GOOS=darwin GOARCH=amd64 go build -o $(BUILD_DIR)/$(APP_NAME)-darwin-amd64 $(MAIN)
	GOOS=darwin GOARCH=arm64 go build -o $(BUILD_DIR)/$(APP_NAME)-darwin-arm64 $(MAIN)
	GOOS=windows GOARCH=amd64 go build -o $(BUILD_DIR)/$(APP_NAME)-windows-amd64.exe $(MAIN)
	@echo "✅ Built all platforms"

# Run directly
run:
	go run $(MAIN) scan --profile $(PROFILE) --region $(REGION)

# Install to GOPATH/bin
install:
	go install $(MAIN)
	@echo "✅ Installed $(APP_NAME) to GOPATH/bin"

# Clean build artifacts
clean:
	rm -rf $(BUILD_DIR)

# Run tests
test:
	go test ./... -v

# Tidy dependencies
tidy:
	go mod tidy

# Download dependencies
deps:
	go mod download
