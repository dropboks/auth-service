package mocks

import (
	"context"
	"time"

	"github.com/dropboks/sharedlib/model"
	m "github.com/stretchr/testify/mock"
)

type MockAuthRepository struct {
	m.Mock
}

func (m *MockAuthRepository) GetResource(ctx context.Context, s string) (string, error) {
	args := m.Called(ctx, s)
	return args.String(0), args.Error(1)
}

func (m *MockAuthRepository) SetResource(ctx context.Context, s1 string, s2 string, t time.Duration) error {
	args := m.Called(ctx, s1, s2, t)
	return args.Error(0)
}

func (m *MockAuthRepository) RemoveResource(ctx context.Context, s string) error {
	args := m.Called(ctx, s)
	return args.Error(0)
}

func (m *MockAuthRepository) GetUserByUserId(userId string) (*model.User, error) {
	args := m.Called(userId)
	user, _ := args.Get(0).(*model.User)
	return user, args.Error(1)
}

func (m *MockAuthRepository) GetUserByEmail(email string) (*model.User, error) {
	args := m.Called(email)
	user, _ := args.Get(0).(*model.User)
	return user, args.Error(1)
}
