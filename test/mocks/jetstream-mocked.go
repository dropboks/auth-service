package mocks

import (
	"context"

	"github.com/nats-io/nats.go/jetstream"
	"github.com/stretchr/testify/mock"
)

type MockNatsInfra struct {
	mock.Mock
}

func (m *MockNatsInfra) Publish(ctx context.Context, subject string, payload []byte) (*jetstream.PubAck, error) {
	args := m.Called(ctx, subject, payload)
	return args.Get(0).(*jetstream.PubAck), args.Error(1)
}
func (m *MockNatsInfra) CreateOrUpdateNewConsumer(ctx context.Context, streamName string, jsConfig *jetstream.ConsumerConfig) (jetstream.Consumer, error) {
	args := m.Called(ctx, streamName, jsConfig)
	return args.Get(0).(jetstream.Consumer), args.Error(1)
}

func (m *MockNatsInfra) CreateOrUpdateNewStream(ctx context.Context, jsConfig *jetstream.StreamConfig) error {
	args := m.Called(ctx, jsConfig)
	return args.Error(0)
}

func (m *MockNatsInfra) GetJetStream() jetstream.JetStream {
	args := m.Called()
	return args.Get(0).(jetstream.JetStream)
}
