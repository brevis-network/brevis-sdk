protoc:
	protoc -I ./brevis-proto \
		--go_out . \
		--go_opt=module=github.com/brevis-network/brevis-sdk  \
		--go_opt=Mcommon/circuit_data.proto=github.com/brevis-network/brevis-sdk/sdk/proto/commonproto  \
		--go_opt=Mbrevis/gateway.proto=github.com/brevis-network/brevis-sdk/sdk/proto/gwproto  \
		--go_opt=Mbrevis/types.proto=github.com/brevis-network/brevis-sdk/sdk/proto/gwproto  \
		--go_opt=Msdk/prover.proto=github.com/brevis-network/brevis-sdk/sdk/proto/sdkproto \
		--go_opt=Msdk/types.proto=github.com/brevis-network/brevis-sdk/sdk/proto/sdkproto \
		--go-grpc_out . \
		--go-grpc_opt=module=github.com/brevis-network/brevis-sdk  \
		--go-grpc_opt=Mcommon/circuit_data.proto=github.com/brevis-network/brevis-sdk/sdk/proto/commonproto  \
		--go-grpc_opt=Mbrevis/gateway.proto=github.com/brevis-network/brevis-sdk/sdk/proto/gwproto  \
		--go-grpc_opt=Mbrevis/types.proto=github.com/brevis-network/brevis-sdk/sdk/proto/gwproto  \
		--go-grpc_opt=Msdk/prover.proto=github.com/brevis-network/brevis-sdk/sdk/proto/sdkproto \
		--go-grpc_opt=Msdk/types.proto=github.com/brevis-network/brevis-sdk/sdk/proto/sdkproto \
		--go-grpc_opt=require_unimplemented_servers=false \
		./brevis-proto/common/circuit_data.proto \
		./brevis-proto/brevis/*.proto \
		./brevis-proto/sdk/*.proto

protoc-prover-gateway:
	protoc -I ./brevis-proto \
		--grpc-gateway_out . \
		--grpc-gateway_opt=module=github.com/brevis-network/brevis-sdk  \
		--grpc-gateway_opt=Msdk/prover.proto=github.com/brevis-network/brevis-sdk/sdk/proto/sdkproto \
		./brevis-proto/sdk/*.proto

protoc-brevis-gateway:
	protoc -I ./brevis-proto \
		--grpc-gateway_out . \
		--grpc-gateway_opt=module=github.com/brevis-network/brevis-sdk  \
		--grpc-gateway_opt=Mbrevis/gateway.proto=github.com/brevis-network/brevis-sdk/sdk/proto/gwproto \
		./brevis-proto/brevis/*.proto
