clean-modules:
	@echo "clean unused module in go.mod and go.sum"
	@go mod tidy