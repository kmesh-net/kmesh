package grpcdata

import (
	"context"
	"log"
	"net"

	"github.com/golang/protobuf/proto"
	"google.golang.org/grpc"
	cluster_v2 "kmesh.net/kmesh/api/v2/cluster"
	core_v2 "kmesh.net/kmesh/api/v2/core"
	pb "kmesh.net/kmesh/api/v2/grpcdata"
	listener_v2 "kmesh.net/kmesh/api/v2/listener"
	route_v2 "kmesh.net/kmesh/api/v2/route"
	maps_v2 "kmesh.net/kmesh/pkg/cache/v2/maps"
)

type server struct {
	pb.UnsafeKmeshMsgServiceServer
}

func handleRequest(req *pb.MsgRequest) error {
	switch req.XdsOpt.XdsNmae {
	case pb.XdsNmae_Cluster:
		valueMsg := &cluster_v2.Cluster{}
		err := proto.Unmarshal(req.Msg, valueMsg)
		if err != nil {
			return err
		}
		switch req.XdsOpt.Opt {
		case pb.Opteration_UPDATE:
			maps_v2.ClusterUpdate(req.Name, valueMsg)
		case pb.Opteration_LOOKUP:
			maps_v2.ClusterLookup(req.Name, valueMsg)
		case pb.Opteration_DELETE:
			maps_v2.ClusterDelete(req.Name)
		}
	case pb.XdsNmae_Listener:
		key := &core_v2.SocketAddress{}
		err := proto.Unmarshal([]byte(req.Name), key)
		if err != nil {
			return err
		}

		valueMsg := &listener_v2.Listener{}
		err = proto.Unmarshal(req.Msg, valueMsg)
		if err != nil {
			return err
		}
		switch req.XdsOpt.Opt {
		case pb.Opteration_UPDATE:
			maps_v2.ListenerUpdate(key, valueMsg)
		case pb.Opteration_LOOKUP:
			maps_v2.ListenerLookup(key, valueMsg)
		case pb.Opteration_DELETE:
			maps_v2.ListenerDelete(key)
		}
	case pb.XdsNmae_Route:
		valueMsg := &route_v2.RouteConfiguration{}
		err := proto.Unmarshal(req.Msg, valueMsg)
		if err != nil {
			return err
		}
		switch req.XdsOpt.Opt {
		case pb.Opteration_UPDATE:
			maps_v2.RouteConfigUpdate(req.Name, valueMsg)
		case pb.Opteration_LOOKUP:
			maps_v2.RouteConfigLookup(req.Name, valueMsg)
		case pb.Opteration_DELETE:
			maps_v2.RouteConfigDelete(req.Name)
		}
	}
	return nil
}

func (s *server) SendMsg(ctx context.Context, req *pb.MsgRequest) (*pb.MsgResponse, error) {
	log.Printf("Received req.Name: %v", req.Name)
	log.Printf("Received req.XdsOpt.Opt %v req.XdsOpt.XdsNmae %v \n ", req.XdsOpt.Opt, req.XdsOpt.XdsNmae)
	//log.Printf("Received req.Msg: %v", req.Msg)

	err := handleRequest(req)
	if err != nil {
		log.Printf("err is : %v", err)
	}
	//log.Printf("valueMsg:\nvalueMsg.ApiStatus:%v\n valueMsg.Name:%v\nvalueMsg.LbPolicy:%v\n valueMsg.LoadAssignment:%v\n valueMsg.ConnectTimeout:%v", valueMsg.ApiStatus, valueMsg.Name, valueMsg.LbPolicy, valueMsg.LoadAssignment, valueMsg.ConnectTimeout)
	return &pb.MsgResponse{ErrorCode: 0}, nil
}

func GrpcInitServer() {
	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer()
	pb.RegisterKmeshMsgServiceServer(s, &server{})
	log.Printf("server listening at %v", lis.Addr())
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
