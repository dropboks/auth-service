package messagequeue

import (
	"context"
	"log"

	"github.com/nats-io/nats.go/jetstream"
	"github.com/spf13/viper"
)

func NewNotificationStream(js jetstream.JetStream) {
	cfg := &jetstream.StreamConfig{
		Name:        viper.GetString("jetstream.notification.stream.name"),
		Description: viper.GetString("jetstream.notification.stream.description"),
		Subjects:    []string{viper.GetString("jetstream.notification.subject.global")},
		MaxBytes:    6 * 1024 * 1024,
		Storage:     jetstream.FileStorage,
	}
	_, err := js.CreateOrUpdateStream(context.Background(), *cfg)
	if err != nil {
		log.Printf("Failed to create or update JetStream stream: %v", err)
	}
}
