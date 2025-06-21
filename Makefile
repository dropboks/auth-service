start:
	@go run ./cmd/main.go
	
clean-modules:
	@echo "clean unused module in go.mod and go.sum"
	@go mod tidy