package mocks

import (
	"context"

	fpb "github.com/dropboks/proto-file/pkg/fpb"
	upb "github.com/dropboks/proto-user/pkg/upb"
	m "github.com/stretchr/testify/mock"
	"google.golang.org/grpc"
)

// MockUserServiceClient mocks the gRPC UserServiceClient
type MockUserServiceClient struct {
	m.Mock
}

func (m *MockUserServiceClient) GetUserByEmail(ctx context.Context, in *upb.Email, opts ...grpc.CallOption) (*upb.User, error) {
	args := m.Called(ctx, in)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*upb.User), args.Error(1)
}

func (m *MockUserServiceClient) GetUserByUserId(ctx context.Context, in *upb.UserId, opts ...grpc.CallOption) (*upb.User, error) {
	args := m.Called(ctx, in)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*upb.User), args.Error(1)
}

func (m *MockUserServiceClient) CreateUser(ctx context.Context, in *upb.User, opts ...grpc.CallOption) (*upb.Status, error) {
	args := m.Called(ctx, in)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*upb.Status), args.Error(1)
}

func (m *MockUserServiceClient) UpdateUser(ctx context.Context, in *upb.User, opts ...grpc.CallOption) (*upb.Status, error) {
	args := m.Called(ctx, in)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*upb.Status), args.Error(1)
}

// MockFileServiceClient mocks the gRPC FileServiceClient
type MockFileServiceClient struct {
	m.Mock
}

func (m *MockFileServiceClient) SaveProfileImage(ctx context.Context, in *fpb.Image, opts ...grpc.CallOption) (*fpb.ImageName, error) {
	args := m.Called(ctx, in)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*fpb.ImageName), args.Error(1)
}

func (m *MockFileServiceClient) RemoveProfileImage(ctx context.Context, in *fpb.ImageName, opts ...grpc.CallOption) (*fpb.Status, error) {
	args := m.Called(ctx, in)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*fpb.Status), args.Error(1)
}
