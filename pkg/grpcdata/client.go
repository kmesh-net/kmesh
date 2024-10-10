package grpcdata

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	pb "kmesh.net/kmesh/api/v2/grpcdata"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

var ConnClient pb.KmeshMsgServiceClient

func SendMsg(c pb.KmeshMsgServiceClient, key string, value []byte) (error, []byte) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	msgRequest := pb.MsgRequest{
		Name:   key,
		XdsOpt: &pb.XdsOpt{XdsNmae: pb.XdsNmae_Cluster, Opt: pb.Opteration_UPDATE},
		Msg:    value,
	}

	r, err := c.SendMsg(ctx, &msgRequest)
	if err != nil {
		log.Fatalf("could not update cluster: %v", err)
		return err, nil
	}
	if r.ErrorCode != 0 {
		return fmt.Errorf("send failed%v", r.ErrorCode), nil
	}
	log.Printf("Cluster update response: %v", r.GetErrorCode())
	return nil, r.Msg
}

func GrpcInitClient() (pb.KmeshMsgServiceClient, *grpc.ClientConn) {

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	addr := os.Getenv("KMESHBPFADDR")
	log.Printf("addr :%v", addr)
	conn, err := grpc.DialContext(ctx, addr, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock())
	if err != nil {
		log.Printf("grpc failed: %v", err)
		return nil, nil
	}
	c := pb.NewKmeshMsgServiceClient(conn)
	ConnClient = c
	log.Printf("client init success")
	return c, conn
}
