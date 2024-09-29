package sdk

import (
	"context"
	"crypto/tls"
	"fmt"

	"github.com/brevis-network/brevis-sdk/sdk/proto/gwproto"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type GatewayClient struct {
	c gwproto.GatewayClient
}

func NewGatewayClient(url ...string) (*GatewayClient, error) {
	if len(url) > 1 {
		panic("must supply at most one url")
	}
	opts := []grpc.DialOption{grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{}))}
	gatewayUrl := "appsdkv2.brevis.network:9094"
	if len(url) > 0 {
		gatewayUrl = url[0]
		// if ovveride, if rpc use http, not https, use WithInsecure
		opts = []grpc.DialOption{grpc.WithInsecure()}
	}
	conn, err := grpc.Dial(gatewayUrl, opts...)
	if err != nil {
		return nil, err
	}
	gc := &GatewayClient{
		c: gwproto.NewGatewayClient(conn),
	}
	return gc, nil
}

func (c *GatewayClient) PrepareQuery(req *gwproto.PrepareQueryRequest) (resp *gwproto.PrepareQueryResponse, err error) {
	resp, err = c.c.PrepareQuery(context.Background(), req)
	if err != nil {
		return nil, err
	}
	if resp.Err != nil {
		return nil, fmt.Errorf("invalid resp, err: %v", resp.Err)
	}
	return
}

func (c *GatewayClient) GetQueryStatus(req *gwproto.GetQueryStatusRequest) (resp *gwproto.GetQueryStatusResponse, err error) {
	resp, err = c.c.GetQueryStatus(context.Background(), req)
	if err != nil {
		return nil, err
	}
	if resp.Err != nil {
		return nil, fmt.Errorf("invalid resp, err: %v", resp.Err)
	}
	return
}

func (c *GatewayClient) SubmitProof(req *gwproto.SubmitAppCircuitProofRequest) (resp *gwproto.SubmitAppCircuitProofResponse, err error) {
	resp, err = c.c.SubmitAppCircuitProof(context.Background(), req)
	if err != nil {
		return nil, err
	}
	if resp.Err != nil {
		return nil, fmt.Errorf("invalid resp, err: %v", resp.Err)
	}
	return
}

func (c *GatewayClient) SendBatchQueries(req *gwproto.SendBatchQueriesRequest) (resp *gwproto.SendBatchQueriesResponse, err error) {
	resp, err = c.c.SendBatchQueries(context.Background(), req)
	if err != nil {
		return nil, err
	}
	if resp.Err != nil {
		return nil, fmt.Errorf("invalid resp, err: %v", resp.Err)
	}
	return
}
