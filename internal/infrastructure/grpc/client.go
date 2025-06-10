package grpc

import (
	fileProto "github.com/dropboks/proto-file/pkg/fpb"
	userProto "github.com/dropboks/proto-user/pkg/upb"
)

func NewUserServiceConnection(manager *GRPCClientManager) userProto.UserServiceClient {
	userServiceConnection := manager.GetConnection("127.0.0.1:50051")
	userServiceClient := userProto.NewUserServiceClient(userServiceConnection)
	return userServiceClient
}

func NewFileServiceConnection(manager *GRPCClientManager) fileProto.FileServiceClient {
	fileServiceConnection := manager.GetConnection("127.0.0.1:50052")
	fileServiceClient := fileProto.NewFileServiceClient(fileServiceConnection)
	return fileServiceClient
}
