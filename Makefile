test:
	go test ./...

lint:
	golangci-lint run
	./ensure-gofmt.sh
