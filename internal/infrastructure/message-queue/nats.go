package messagequeue

import (
	"context"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/rs/zerolog"
)

type (
	Nats interface {
		CreateOrUpdateNewConsumer(ctx context.Context, streamName string, jsConfig *jetstream.ConsumerConfig) (jetstream.Consumer, error)
		CreateOrUpdateNewStream(ctx context.Context, jsConfig *jetstream.StreamConfig) error
		Publish(ctx context.Context, subject string, payload []byte) (*jetstream.PubAck, error)
		GetJetStream() jetstream.JetStream
	}
	natsInstance struct {
		nc     *nats.Conn
		js     jetstream.JetStream
		logger zerolog.Logger
	}
)

func NewNatsInfrastructure(nc *nats.Conn, logger zerolog.Logger, js jetstream.JetStream) Nats {
	return &natsInstance{
		nc:     nc,
		logger: logger,
		js:     js,
	}
}

func (n *natsInstance) GetJetStream() jetstream.JetStream {
	return n.js
}

func (n *natsInstance) CreateOrUpdateNewConsumer(ctx context.Context, streamName string, jsConfig *jetstream.ConsumerConfig) (jetstream.Consumer, error) {
	stream, err := n.js.Stream(ctx, streamName)
	if err != nil {
		n.logger.Fatal().Err(err).Msg("failed to get stream")
	}
	cons, err := stream.CreateOrUpdateConsumer(ctx, *jsConfig)
	if err != nil {
		n.logger.Error().Err(err).Msg("failed to create or update consumer")
		return nil, err
	}
	return cons, nil
}

func (n *natsInstance) CreateOrUpdateNewStream(ctx context.Context, jsConfig *jetstream.StreamConfig) error {
	_, err := n.js.CreateOrUpdateStream(ctx, *jsConfig)
	if err != nil {
		n.logger.Error().Err(err).Msg("error create or update the stream")
		return err
	}
	return nil
}

func (n *natsInstance) Publish(ctx context.Context, subject string, payload []byte) (*jetstream.PubAck, error) {
	ack, err := n.js.Publish(ctx, subject, payload)
	if err != nil {
		return nil, err
	}
	return ack, nil
}
