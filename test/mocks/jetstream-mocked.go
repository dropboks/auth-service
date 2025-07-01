package mocks

import (
	"context"

	"github.com/nats-io/nats.go/jetstream"
	"github.com/stretchr/testify/mock"
)

type MockJetStreamInfra struct {
	mock.Mock
}

func (m *MockJetStreamInfra) Publish(ctx context.Context, subject string, payload []byte) (*jetstream.PubAck, error) {
	args := m.Called(ctx, subject, payload)
	return args.Get(0).(*jetstream.PubAck), args.Error(1)
}
