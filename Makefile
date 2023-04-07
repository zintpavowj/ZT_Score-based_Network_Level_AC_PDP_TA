MODULE=ztsnlac_pdp_ta
GO_BUILD_TARGET=./cmd/$(MODULE)/main.go

.PHONY: main
main: go

.PHONY: go
go:
	git pull
	go mod tidy
	go build -o $(MODULE) -v $(GO_BUILD_TARGET)
