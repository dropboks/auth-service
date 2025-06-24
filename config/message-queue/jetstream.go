package messagequeue

import (
	"context"
	"log"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/spf13/viper"
)

func NewJetstream(nc *nats.Conn) jetstream.JetStream {
	js, err := jetstream.New(nc)
	if err != nil {
		panic("failed to init jetstream")
	}
	cfg := &jetstream.StreamConfig{
		Name:        viper.GetString("jetstream.stream.name"),
		Description: viper.GetString("jetstream.stream.description"),
		Subjects:    []string{viper.GetString("jetstream.subject.global")},
		MaxBytes:    10 * 1024 * 1024,
		Storage:     jetstream.FileStorage,
	}
	_, err = js.CreateOrUpdateStream(context.Background(), *cfg)
	if err != nil {
		log.Printf("Failed to create or update JetStream stream: %v", err)
		return nil
	}
	return js
}
