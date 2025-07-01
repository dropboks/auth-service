package messagequeue

import (
	"context"

	"github.com/nats-io/nats.go/jetstream"
	"github.com/rs/zerolog"
)

type (
	JetStreamInfra interface {
		Publish(context.Context, string, []byte) (*jetstream.PubAck, error)
	}
	jetStreamInfra struct {
		js     jetstream.JetStream
		logger zerolog.Logger
	}
)

func NewJetstreamInfra(js jetstream.JetStream, logger zerolog.Logger) JetStreamInfra {
	return &jetStreamInfra{
		js:     js,
		logger: logger,
	}
}

func (j *jetStreamInfra) Publish(ctx context.Context, subject string, payload []byte) (*jetstream.PubAck, error) {
	ack, err := j.js.Publish(ctx, subject, payload)
	if err != nil {
		return nil, err
	}
	return ack, nil
}
