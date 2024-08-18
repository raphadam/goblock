.PHONY: gen2 gen

gen2:
	protoc -I=./common/schema --go_out=./common --go-grpc_out=./common ./common/schema/*.proto

gen:
	protoc --go_out=. --go_opt=paths=source_relative \
	--go-grpc_out=. --go-grpc_opt=paths=source_relative \
	pb/*.proto
