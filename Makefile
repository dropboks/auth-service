.PHONY: pre-commit

start:
	@go run ./cmd/main.go
	
clean-modules:
	@echo "clean unused module in go.mod and go.sum"
	@go mod tidy

air-windows:
	@air -c .air.win.toml

air-unix:
	@~/go/bin/air -c .air.unix.toml

pre-commit:
	@echo "Checking staged Go files..."
	@STAGED_GO_FILES=$$(git diff --cached --name-only --diff-filter=ACM | grep '\.go$$' || true); \
	if [ -n "$$STAGED_GO_FILES" ]; then \
		echo "Running go fmt on staged files..."; \
		UNFORMATTED=$$(gofmt -l $$STAGED_GO_FILES); \
		if [ -n "$$UNFORMATTED" ]; then \
			echo "[✗] The following staged Go files are not properly formatted:"; \
			echo "$$UNFORMATTED"; \
			exit 1; \
		else \
			echo "[✓] All staged Go files are properly formatted."; \
		fi \
	else \
		echo "No staged Go files to check."; \
	fi

	@echo "Running go vet..."
	@go vet ./... || (echo "[✗] go vet failed." && exit 1)

	@echo "Running go test (it/ut/e2e)..."
	@go test ./test/it/... ./test/ut/... ./test/e2e/... || (echo "[✗] Tests failed." && exit 1)

	@echo "[✓] Pre-commit checks passed!"

pre-commit-preparation:
	@cp ./bin/pre-commit ./.git/hooks/pre-commit
	@chmod +x ./.git/hooks/pre-commit