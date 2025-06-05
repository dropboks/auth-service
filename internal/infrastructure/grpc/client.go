package grpc

import (
	fileProto "github.com/dropboks/proto-file/pkg/fpb"
	userProto "github.com/dropboks/proto-user/pkg/upb"
)

func NewUserServiceConnection(manager *GRPCClientManager) userProto.UserServiceClient {
	userServiceConnection := manager.GetConnection("user_service:50051")
	userServiceClient := userProto.NewUserServiceClient(userServiceConnection)
	return userServiceClient
}

func NewFileServiceConnection(manager *GRPCClientManager) fileProto.FileServiceClient {
	fileServiceConnection := manager.GetConnection("file_service:50051")
	fileServiceClient := fileProto.NewFileServiceClient(fileServiceConnection)
	return fileServiceClient
}
