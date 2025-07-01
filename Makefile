start:
	@go run ./cmd/main.go
	
clean-modules:
	@echo "clean unused module in go.mod and go.sum"
	@go mod tidy

air-windows:
	@air -c .air.win.toml
air-unix:
	@~/go/bin/air -c .air.unix.toml
