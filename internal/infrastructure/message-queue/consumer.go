package messagequeue

import (
	event "github.com/dropboks/event-bus-client/pkg/event/user"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/rs/zerolog"
	"github.com/spf13/viper"
)

func NewUserEventConsumerInfra(pgx *pgxpool.Pool, n Nats, logger zerolog.Logger) event.UserEventConsumer {
	cfg := jetstream.ConsumerConfig{
		Name:          viper.GetString("jetstream.consumer.user_event.name"),
		Durable:       viper.GetString("jetstream.consumer.user_event.name"),
		FilterSubject: viper.GetString("jetstream.consumer.user_event.subject"),
		AckPolicy:     jetstream.AckExplicitPolicy,
		DeliverPolicy: jetstream.DeliverNewPolicy,
	}
	con := event.NewUserEventConsumer(pgx, n.GetJetStream(), cfg, logger)
	return con
}
