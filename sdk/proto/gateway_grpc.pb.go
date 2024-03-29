// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.3.0
// - protoc             v4.24.3
// source: gateway.proto

package proto

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.32.0 or later.
const _ = grpc.SupportPackageIsVersion7

const (
	Web_GetTokens_FullMethodName                     = "/zk.gateway.Web/GetTokens"
	Web_GetHistory_FullMethodName                    = "/zk.gateway.Web/GetHistory"
	Web_GetTransfer_FullMethodName                   = "/zk.gateway.Web/GetTransfer"
	Web_GetProofData_FullMethodName                  = "/zk.gateway.Web/GetProofData"
	Web_GetRecentAttestedSlots_FullMethodName        = "/zk.gateway.Web/GetRecentAttestedSlots"
	Web_GenerateSlotValueProof_FullMethodName        = "/zk.gateway.Web/GenerateSlotValueProof"
	Web_GetProof_FullMethodName                      = "/zk.gateway.Web/GetProof"
	Web_GenerateTransactionProof_FullMethodName      = "/zk.gateway.Web/GenerateTransactionProof"
	Web_GenerateReceiptProof_FullMethodName          = "/zk.gateway.Web/GenerateReceiptProof"
	Web_GetRecentAttestedTransactions_FullMethodName = "/zk.gateway.Web/GetRecentAttestedTransactions"
	Web_CheckUniNFTEligibility_FullMethodName        = "/zk.gateway.Web/CheckUniNFTEligibility"
	Web_GetSocialGraphData_FullMethodName            = "/zk.gateway.Web/GetSocialGraphData"
	Web_GetRecentAttestedFriendShip_FullMethodName   = "/zk.gateway.Web/GetRecentAttestedFriendShip"
	Web_CheckFriendShip_FullMethodName               = "/zk.gateway.Web/CheckFriendShip"
	Web_GetUniswapLeaderboard_FullMethodName         = "/zk.gateway.Web/GetUniswapLeaderboard"
	Web_CheckUniswapSumVolume_FullMethodName         = "/zk.gateway.Web/CheckUniswapSumVolume"
	Web_GenerateUniswapSumProof_FullMethodName       = "/zk.gateway.Web/GenerateUniswapSumProof"
	Web_GetUserTierAvailability_FullMethodName       = "/zk.gateway.Web/GetUserTierAvailability"
	Web_PrepareQuery_FullMethodName                  = "/zk.gateway.Web/PrepareQuery"
	Web_RetrieveQueryAndProof_FullMethodName         = "/zk.gateway.Web/RetrieveQueryAndProof"
	Web_SubmitAppCircuitProof_FullMethodName         = "/zk.gateway.Web/SubmitAppCircuitProof"
	Web_GetQueryStatus_FullMethodName                = "/zk.gateway.Web/GetQueryStatus"
)

// WebClient is the client api for Web service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type WebClient interface {
	GetTokens(ctx context.Context, in *GetTokensRequest, opts ...grpc.CallOption) (*GetTokensResponse, error)
	GetHistory(ctx context.Context, in *GetHistoryRequest, opts ...grpc.CallOption) (*GetHistoryResponse, error)
	GetTransfer(ctx context.Context, in *GetTransferRequest, opts ...grpc.CallOption) (*GetTransferResponse, error)
	GetProofData(ctx context.Context, in *GetProofDataRequest, opts ...grpc.CallOption) (*GetProofDataResponse, error)
	// get latest 5 attested slot
	GetRecentAttestedSlots(ctx context.Context, in *GetRecentAttestedSlotRequest, opts ...grpc.CallOption) (*GetRecentAttestedSlotResponse, error)
	GenerateSlotValueProof(ctx context.Context, in *GenerateSlotValueProofRequest, opts ...grpc.CallOption) (*GenerateSlotValueProofResponse, error)
	GetProof(ctx context.Context, in *GetProofRequest, opts ...grpc.CallOption) (*GetProofResponse, error)
	GenerateTransactionProof(ctx context.Context, in *GenerateTransactionProofRequest, opts ...grpc.CallOption) (*GenerateTransactionProofResponse, error)
	GenerateReceiptProof(ctx context.Context, in *GenerateReceiptProofRequest, opts ...grpc.CallOption) (*GenerateReceiptProofResponse, error)
	// get latest 5 attested transactions
	GetRecentAttestedTransactions(ctx context.Context, in *AttestedTransactionsRequest, opts ...grpc.CallOption) (*AttestedTransactionsResponse, error)
	CheckUniNFTEligibility(ctx context.Context, in *CheckUniNFTEligibilityRequest, opts ...grpc.CallOption) (*CheckUniNFTEligibilityResponse, error)
	GetSocialGraphData(ctx context.Context, in *GetSocialGraphDataRequest, opts ...grpc.CallOption) (*GetSocialGraphDataResponse, error)
	// Get 5 recent attested friend ship records
	GetRecentAttestedFriendShip(ctx context.Context, in *GetAttestedFriendShipRequest, opts ...grpc.CallOption) (*GetAttestedFriendShipResponse, error)
	CheckFriendShip(ctx context.Context, in *CheckFriendShipRequest, opts ...grpc.CallOption) (*CheckFriendShipResponse, error)
	GetUniswapLeaderboard(ctx context.Context, in *GetUniswapLeaderboardRequest, opts ...grpc.CallOption) (*GetUniswapLeaderboardResponse, error)
	CheckUniswapSumVolume(ctx context.Context, in *CheckUniswapSumVolumeRequest, opts ...grpc.CallOption) (*CheckUniswapSumVolumeResponse, error)
	GenerateUniswapSumProof(ctx context.Context, in *GenerateUniswapSumProofRequest, opts ...grpc.CallOption) (*GenerateUniswapSumProofResponse, error)
	GetUserTierAvailability(ctx context.Context, in *GetUserTierAvailabilityRequest, opts ...grpc.CallOption) (*GetUserTierAvailabilityResponse, error)
	PrepareQuery(ctx context.Context, in *PrepareQueryRequest, opts ...grpc.CallOption) (*PrepareQueryResponse, error)
	RetrieveQueryAndProof(ctx context.Context, in *RetrieveQueryAndProofRequest, opts ...grpc.CallOption) (*RetrieveQueryAndProofResponse, error)
	SubmitAppCircuitProof(ctx context.Context, in *SubmitAppCircuitProofRequest, opts ...grpc.CallOption) (*SubmitAppCircuitProofResponse, error)
	GetQueryStatus(ctx context.Context, in *GetQueryStatusRequest, opts ...grpc.CallOption) (*GetQueryStatusResponse, error)
}

type webClient struct {
	cc grpc.ClientConnInterface
}

func NewWebClient(cc grpc.ClientConnInterface) WebClient {
	return &webClient{cc}
}

func (c *webClient) GetTokens(ctx context.Context, in *GetTokensRequest, opts ...grpc.CallOption) (*GetTokensResponse, error) {
	out := new(GetTokensResponse)
	err := c.cc.Invoke(ctx, Web_GetTokens_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *webClient) GetHistory(ctx context.Context, in *GetHistoryRequest, opts ...grpc.CallOption) (*GetHistoryResponse, error) {
	out := new(GetHistoryResponse)
	err := c.cc.Invoke(ctx, Web_GetHistory_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *webClient) GetTransfer(ctx context.Context, in *GetTransferRequest, opts ...grpc.CallOption) (*GetTransferResponse, error) {
	out := new(GetTransferResponse)
	err := c.cc.Invoke(ctx, Web_GetTransfer_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *webClient) GetProofData(ctx context.Context, in *GetProofDataRequest, opts ...grpc.CallOption) (*GetProofDataResponse, error) {
	out := new(GetProofDataResponse)
	err := c.cc.Invoke(ctx, Web_GetProofData_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *webClient) GetRecentAttestedSlots(ctx context.Context, in *GetRecentAttestedSlotRequest, opts ...grpc.CallOption) (*GetRecentAttestedSlotResponse, error) {
	out := new(GetRecentAttestedSlotResponse)
	err := c.cc.Invoke(ctx, Web_GetRecentAttestedSlots_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *webClient) GenerateSlotValueProof(ctx context.Context, in *GenerateSlotValueProofRequest, opts ...grpc.CallOption) (*GenerateSlotValueProofResponse, error) {
	out := new(GenerateSlotValueProofResponse)
	err := c.cc.Invoke(ctx, Web_GenerateSlotValueProof_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *webClient) GetProof(ctx context.Context, in *GetProofRequest, opts ...grpc.CallOption) (*GetProofResponse, error) {
	out := new(GetProofResponse)
	err := c.cc.Invoke(ctx, Web_GetProof_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *webClient) GenerateTransactionProof(ctx context.Context, in *GenerateTransactionProofRequest, opts ...grpc.CallOption) (*GenerateTransactionProofResponse, error) {
	out := new(GenerateTransactionProofResponse)
	err := c.cc.Invoke(ctx, Web_GenerateTransactionProof_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *webClient) GenerateReceiptProof(ctx context.Context, in *GenerateReceiptProofRequest, opts ...grpc.CallOption) (*GenerateReceiptProofResponse, error) {
	out := new(GenerateReceiptProofResponse)
	err := c.cc.Invoke(ctx, Web_GenerateReceiptProof_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *webClient) GetRecentAttestedTransactions(ctx context.Context, in *AttestedTransactionsRequest, opts ...grpc.CallOption) (*AttestedTransactionsResponse, error) {
	out := new(AttestedTransactionsResponse)
	err := c.cc.Invoke(ctx, Web_GetRecentAttestedTransactions_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *webClient) CheckUniNFTEligibility(ctx context.Context, in *CheckUniNFTEligibilityRequest, opts ...grpc.CallOption) (*CheckUniNFTEligibilityResponse, error) {
	out := new(CheckUniNFTEligibilityResponse)
	err := c.cc.Invoke(ctx, Web_CheckUniNFTEligibility_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *webClient) GetSocialGraphData(ctx context.Context, in *GetSocialGraphDataRequest, opts ...grpc.CallOption) (*GetSocialGraphDataResponse, error) {
	out := new(GetSocialGraphDataResponse)
	err := c.cc.Invoke(ctx, Web_GetSocialGraphData_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *webClient) GetRecentAttestedFriendShip(ctx context.Context, in *GetAttestedFriendShipRequest, opts ...grpc.CallOption) (*GetAttestedFriendShipResponse, error) {
	out := new(GetAttestedFriendShipResponse)
	err := c.cc.Invoke(ctx, Web_GetRecentAttestedFriendShip_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *webClient) CheckFriendShip(ctx context.Context, in *CheckFriendShipRequest, opts ...grpc.CallOption) (*CheckFriendShipResponse, error) {
	out := new(CheckFriendShipResponse)
	err := c.cc.Invoke(ctx, Web_CheckFriendShip_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *webClient) GetUniswapLeaderboard(ctx context.Context, in *GetUniswapLeaderboardRequest, opts ...grpc.CallOption) (*GetUniswapLeaderboardResponse, error) {
	out := new(GetUniswapLeaderboardResponse)
	err := c.cc.Invoke(ctx, Web_GetUniswapLeaderboard_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *webClient) CheckUniswapSumVolume(ctx context.Context, in *CheckUniswapSumVolumeRequest, opts ...grpc.CallOption) (*CheckUniswapSumVolumeResponse, error) {
	out := new(CheckUniswapSumVolumeResponse)
	err := c.cc.Invoke(ctx, Web_CheckUniswapSumVolume_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *webClient) GenerateUniswapSumProof(ctx context.Context, in *GenerateUniswapSumProofRequest, opts ...grpc.CallOption) (*GenerateUniswapSumProofResponse, error) {
	out := new(GenerateUniswapSumProofResponse)
	err := c.cc.Invoke(ctx, Web_GenerateUniswapSumProof_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *webClient) GetUserTierAvailability(ctx context.Context, in *GetUserTierAvailabilityRequest, opts ...grpc.CallOption) (*GetUserTierAvailabilityResponse, error) {
	out := new(GetUserTierAvailabilityResponse)
	err := c.cc.Invoke(ctx, Web_GetUserTierAvailability_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *webClient) PrepareQuery(ctx context.Context, in *PrepareQueryRequest, opts ...grpc.CallOption) (*PrepareQueryResponse, error) {
	out := new(PrepareQueryResponse)
	err := c.cc.Invoke(ctx, Web_PrepareQuery_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *webClient) RetrieveQueryAndProof(ctx context.Context, in *RetrieveQueryAndProofRequest, opts ...grpc.CallOption) (*RetrieveQueryAndProofResponse, error) {
	out := new(RetrieveQueryAndProofResponse)
	err := c.cc.Invoke(ctx, Web_RetrieveQueryAndProof_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *webClient) SubmitAppCircuitProof(ctx context.Context, in *SubmitAppCircuitProofRequest, opts ...grpc.CallOption) (*SubmitAppCircuitProofResponse, error) {
	out := new(SubmitAppCircuitProofResponse)
	err := c.cc.Invoke(ctx, Web_SubmitAppCircuitProof_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *webClient) GetQueryStatus(ctx context.Context, in *GetQueryStatusRequest, opts ...grpc.CallOption) (*GetQueryStatusResponse, error) {
	out := new(GetQueryStatusResponse)
	err := c.cc.Invoke(ctx, Web_GetQueryStatus_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// WebServer is the server api for Web service.
// All implementations should embed UnimplementedWebServer
// for forward compatibility
type WebServer interface {
	GetTokens(context.Context, *GetTokensRequest) (*GetTokensResponse, error)
	GetHistory(context.Context, *GetHistoryRequest) (*GetHistoryResponse, error)
	GetTransfer(context.Context, *GetTransferRequest) (*GetTransferResponse, error)
	GetProofData(context.Context, *GetProofDataRequest) (*GetProofDataResponse, error)
	// get latest 5 attested slot
	GetRecentAttestedSlots(context.Context, *GetRecentAttestedSlotRequest) (*GetRecentAttestedSlotResponse, error)
	GenerateSlotValueProof(context.Context, *GenerateSlotValueProofRequest) (*GenerateSlotValueProofResponse, error)
	GetProof(context.Context, *GetProofRequest) (*GetProofResponse, error)
	GenerateTransactionProof(context.Context, *GenerateTransactionProofRequest) (*GenerateTransactionProofResponse, error)
	GenerateReceiptProof(context.Context, *GenerateReceiptProofRequest) (*GenerateReceiptProofResponse, error)
	// get latest 5 attested transactions
	GetRecentAttestedTransactions(context.Context, *AttestedTransactionsRequest) (*AttestedTransactionsResponse, error)
	CheckUniNFTEligibility(context.Context, *CheckUniNFTEligibilityRequest) (*CheckUniNFTEligibilityResponse, error)
	GetSocialGraphData(context.Context, *GetSocialGraphDataRequest) (*GetSocialGraphDataResponse, error)
	// Get 5 recent attested friend ship records
	GetRecentAttestedFriendShip(context.Context, *GetAttestedFriendShipRequest) (*GetAttestedFriendShipResponse, error)
	CheckFriendShip(context.Context, *CheckFriendShipRequest) (*CheckFriendShipResponse, error)
	GetUniswapLeaderboard(context.Context, *GetUniswapLeaderboardRequest) (*GetUniswapLeaderboardResponse, error)
	CheckUniswapSumVolume(context.Context, *CheckUniswapSumVolumeRequest) (*CheckUniswapSumVolumeResponse, error)
	GenerateUniswapSumProof(context.Context, *GenerateUniswapSumProofRequest) (*GenerateUniswapSumProofResponse, error)
	GetUserTierAvailability(context.Context, *GetUserTierAvailabilityRequest) (*GetUserTierAvailabilityResponse, error)
	PrepareQuery(context.Context, *PrepareQueryRequest) (*PrepareQueryResponse, error)
	RetrieveQueryAndProof(context.Context, *RetrieveQueryAndProofRequest) (*RetrieveQueryAndProofResponse, error)
	SubmitAppCircuitProof(context.Context, *SubmitAppCircuitProofRequest) (*SubmitAppCircuitProofResponse, error)
	GetQueryStatus(context.Context, *GetQueryStatusRequest) (*GetQueryStatusResponse, error)
}

// UnimplementedWebServer should be embedded to have forward compatible implementations.
type UnimplementedWebServer struct {
}

func (UnimplementedWebServer) GetTokens(context.Context, *GetTokensRequest) (*GetTokensResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetTokens not implemented")
}
func (UnimplementedWebServer) GetHistory(context.Context, *GetHistoryRequest) (*GetHistoryResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetHistory not implemented")
}
func (UnimplementedWebServer) GetTransfer(context.Context, *GetTransferRequest) (*GetTransferResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetTransfer not implemented")
}
func (UnimplementedWebServer) GetProofData(context.Context, *GetProofDataRequest) (*GetProofDataResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetProofData not implemented")
}
func (UnimplementedWebServer) GetRecentAttestedSlots(context.Context, *GetRecentAttestedSlotRequest) (*GetRecentAttestedSlotResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetRecentAttestedSlots not implemented")
}
func (UnimplementedWebServer) GenerateSlotValueProof(context.Context, *GenerateSlotValueProofRequest) (*GenerateSlotValueProofResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GenerateSlotValueProof not implemented")
}
func (UnimplementedWebServer) GetProof(context.Context, *GetProofRequest) (*GetProofResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetProof not implemented")
}
func (UnimplementedWebServer) GenerateTransactionProof(context.Context, *GenerateTransactionProofRequest) (*GenerateTransactionProofResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GenerateTransactionProof not implemented")
}
func (UnimplementedWebServer) GenerateReceiptProof(context.Context, *GenerateReceiptProofRequest) (*GenerateReceiptProofResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GenerateReceiptProof not implemented")
}
func (UnimplementedWebServer) GetRecentAttestedTransactions(context.Context, *AttestedTransactionsRequest) (*AttestedTransactionsResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetRecentAttestedTransactions not implemented")
}
func (UnimplementedWebServer) CheckUniNFTEligibility(context.Context, *CheckUniNFTEligibilityRequest) (*CheckUniNFTEligibilityResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CheckUniNFTEligibility not implemented")
}
func (UnimplementedWebServer) GetSocialGraphData(context.Context, *GetSocialGraphDataRequest) (*GetSocialGraphDataResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetSocialGraphData not implemented")
}
func (UnimplementedWebServer) GetRecentAttestedFriendShip(context.Context, *GetAttestedFriendShipRequest) (*GetAttestedFriendShipResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetRecentAttestedFriendShip not implemented")
}
func (UnimplementedWebServer) CheckFriendShip(context.Context, *CheckFriendShipRequest) (*CheckFriendShipResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CheckFriendShip not implemented")
}
func (UnimplementedWebServer) GetUniswapLeaderboard(context.Context, *GetUniswapLeaderboardRequest) (*GetUniswapLeaderboardResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetUniswapLeaderboard not implemented")
}
func (UnimplementedWebServer) CheckUniswapSumVolume(context.Context, *CheckUniswapSumVolumeRequest) (*CheckUniswapSumVolumeResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CheckUniswapSumVolume not implemented")
}
func (UnimplementedWebServer) GenerateUniswapSumProof(context.Context, *GenerateUniswapSumProofRequest) (*GenerateUniswapSumProofResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GenerateUniswapSumProof not implemented")
}
func (UnimplementedWebServer) GetUserTierAvailability(context.Context, *GetUserTierAvailabilityRequest) (*GetUserTierAvailabilityResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetUserTierAvailability not implemented")
}
func (UnimplementedWebServer) PrepareQuery(context.Context, *PrepareQueryRequest) (*PrepareQueryResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method PrepareQuery not implemented")
}
func (UnimplementedWebServer) RetrieveQueryAndProof(context.Context, *RetrieveQueryAndProofRequest) (*RetrieveQueryAndProofResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method RetrieveQueryAndProof not implemented")
}
func (UnimplementedWebServer) SubmitAppCircuitProof(context.Context, *SubmitAppCircuitProofRequest) (*SubmitAppCircuitProofResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method SubmitAppCircuitProof not implemented")
}
func (UnimplementedWebServer) GetQueryStatus(context.Context, *GetQueryStatusRequest) (*GetQueryStatusResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetQueryStatus not implemented")
}

// UnsafeWebServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to WebServer will
// result in compilation errors.
type UnsafeWebServer interface {
	mustEmbedUnimplementedWebServer()
}

func RegisterWebServer(s grpc.ServiceRegistrar, srv WebServer) {
	s.RegisterService(&Web_ServiceDesc, srv)
}

func _Web_GetTokens_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetTokensRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(WebServer).GetTokens(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Web_GetTokens_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(WebServer).GetTokens(ctx, req.(*GetTokensRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Web_GetHistory_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetHistoryRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(WebServer).GetHistory(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Web_GetHistory_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(WebServer).GetHistory(ctx, req.(*GetHistoryRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Web_GetTransfer_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetTransferRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(WebServer).GetTransfer(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Web_GetTransfer_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(WebServer).GetTransfer(ctx, req.(*GetTransferRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Web_GetProofData_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetProofDataRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(WebServer).GetProofData(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Web_GetProofData_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(WebServer).GetProofData(ctx, req.(*GetProofDataRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Web_GetRecentAttestedSlots_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetRecentAttestedSlotRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(WebServer).GetRecentAttestedSlots(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Web_GetRecentAttestedSlots_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(WebServer).GetRecentAttestedSlots(ctx, req.(*GetRecentAttestedSlotRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Web_GenerateSlotValueProof_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GenerateSlotValueProofRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(WebServer).GenerateSlotValueProof(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Web_GenerateSlotValueProof_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(WebServer).GenerateSlotValueProof(ctx, req.(*GenerateSlotValueProofRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Web_GetProof_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetProofRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(WebServer).GetProof(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Web_GetProof_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(WebServer).GetProof(ctx, req.(*GetProofRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Web_GenerateTransactionProof_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GenerateTransactionProofRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(WebServer).GenerateTransactionProof(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Web_GenerateTransactionProof_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(WebServer).GenerateTransactionProof(ctx, req.(*GenerateTransactionProofRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Web_GenerateReceiptProof_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GenerateReceiptProofRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(WebServer).GenerateReceiptProof(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Web_GenerateReceiptProof_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(WebServer).GenerateReceiptProof(ctx, req.(*GenerateReceiptProofRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Web_GetRecentAttestedTransactions_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(AttestedTransactionsRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(WebServer).GetRecentAttestedTransactions(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Web_GetRecentAttestedTransactions_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(WebServer).GetRecentAttestedTransactions(ctx, req.(*AttestedTransactionsRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Web_CheckUniNFTEligibility_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CheckUniNFTEligibilityRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(WebServer).CheckUniNFTEligibility(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Web_CheckUniNFTEligibility_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(WebServer).CheckUniNFTEligibility(ctx, req.(*CheckUniNFTEligibilityRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Web_GetSocialGraphData_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetSocialGraphDataRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(WebServer).GetSocialGraphData(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Web_GetSocialGraphData_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(WebServer).GetSocialGraphData(ctx, req.(*GetSocialGraphDataRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Web_GetRecentAttestedFriendShip_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetAttestedFriendShipRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(WebServer).GetRecentAttestedFriendShip(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Web_GetRecentAttestedFriendShip_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(WebServer).GetRecentAttestedFriendShip(ctx, req.(*GetAttestedFriendShipRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Web_CheckFriendShip_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CheckFriendShipRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(WebServer).CheckFriendShip(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Web_CheckFriendShip_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(WebServer).CheckFriendShip(ctx, req.(*CheckFriendShipRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Web_GetUniswapLeaderboard_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetUniswapLeaderboardRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(WebServer).GetUniswapLeaderboard(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Web_GetUniswapLeaderboard_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(WebServer).GetUniswapLeaderboard(ctx, req.(*GetUniswapLeaderboardRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Web_CheckUniswapSumVolume_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CheckUniswapSumVolumeRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(WebServer).CheckUniswapSumVolume(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Web_CheckUniswapSumVolume_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(WebServer).CheckUniswapSumVolume(ctx, req.(*CheckUniswapSumVolumeRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Web_GenerateUniswapSumProof_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GenerateUniswapSumProofRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(WebServer).GenerateUniswapSumProof(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Web_GenerateUniswapSumProof_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(WebServer).GenerateUniswapSumProof(ctx, req.(*GenerateUniswapSumProofRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Web_GetUserTierAvailability_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetUserTierAvailabilityRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(WebServer).GetUserTierAvailability(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Web_GetUserTierAvailability_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(WebServer).GetUserTierAvailability(ctx, req.(*GetUserTierAvailabilityRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Web_PrepareQuery_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(PrepareQueryRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(WebServer).PrepareQuery(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Web_PrepareQuery_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(WebServer).PrepareQuery(ctx, req.(*PrepareQueryRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Web_RetrieveQueryAndProof_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(RetrieveQueryAndProofRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(WebServer).RetrieveQueryAndProof(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Web_RetrieveQueryAndProof_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(WebServer).RetrieveQueryAndProof(ctx, req.(*RetrieveQueryAndProofRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Web_SubmitAppCircuitProof_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(SubmitAppCircuitProofRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(WebServer).SubmitAppCircuitProof(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Web_SubmitAppCircuitProof_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(WebServer).SubmitAppCircuitProof(ctx, req.(*SubmitAppCircuitProofRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Web_GetQueryStatus_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetQueryStatusRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(WebServer).GetQueryStatus(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Web_GetQueryStatus_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(WebServer).GetQueryStatus(ctx, req.(*GetQueryStatusRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// Web_ServiceDesc is the grpc.ServiceDesc for Web service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var Web_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "zk.gateway.Web",
	HandlerType: (*WebServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "GetTokens",
			Handler:    _Web_GetTokens_Handler,
		},
		{
			MethodName: "GetHistory",
			Handler:    _Web_GetHistory_Handler,
		},
		{
			MethodName: "GetTransfer",
			Handler:    _Web_GetTransfer_Handler,
		},
		{
			MethodName: "GetProofData",
			Handler:    _Web_GetProofData_Handler,
		},
		{
			MethodName: "GetRecentAttestedSlots",
			Handler:    _Web_GetRecentAttestedSlots_Handler,
		},
		{
			MethodName: "GenerateSlotValueProof",
			Handler:    _Web_GenerateSlotValueProof_Handler,
		},
		{
			MethodName: "GetProof",
			Handler:    _Web_GetProof_Handler,
		},
		{
			MethodName: "GenerateTransactionProof",
			Handler:    _Web_GenerateTransactionProof_Handler,
		},
		{
			MethodName: "GenerateReceiptProof",
			Handler:    _Web_GenerateReceiptProof_Handler,
		},
		{
			MethodName: "GetRecentAttestedTransactions",
			Handler:    _Web_GetRecentAttestedTransactions_Handler,
		},
		{
			MethodName: "CheckUniNFTEligibility",
			Handler:    _Web_CheckUniNFTEligibility_Handler,
		},
		{
			MethodName: "GetSocialGraphData",
			Handler:    _Web_GetSocialGraphData_Handler,
		},
		{
			MethodName: "GetRecentAttestedFriendShip",
			Handler:    _Web_GetRecentAttestedFriendShip_Handler,
		},
		{
			MethodName: "CheckFriendShip",
			Handler:    _Web_CheckFriendShip_Handler,
		},
		{
			MethodName: "GetUniswapLeaderboard",
			Handler:    _Web_GetUniswapLeaderboard_Handler,
		},
		{
			MethodName: "CheckUniswapSumVolume",
			Handler:    _Web_CheckUniswapSumVolume_Handler,
		},
		{
			MethodName: "GenerateUniswapSumProof",
			Handler:    _Web_GenerateUniswapSumProof_Handler,
		},
		{
			MethodName: "GetUserTierAvailability",
			Handler:    _Web_GetUserTierAvailability_Handler,
		},
		{
			MethodName: "PrepareQuery",
			Handler:    _Web_PrepareQuery_Handler,
		},
		{
			MethodName: "RetrieveQueryAndProof",
			Handler:    _Web_RetrieveQueryAndProof_Handler,
		},
		{
			MethodName: "SubmitAppCircuitProof",
			Handler:    _Web_SubmitAppCircuitProof_Handler,
		},
		{
			MethodName: "GetQueryStatus",
			Handler:    _Web_GetQueryStatus_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "gateway.proto",
}
