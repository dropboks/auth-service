package env

import (
	"os"

	"github.com/spf13/viper"
)

func Load() {
	env := os.Getenv("ENV")
	configName := "config"
	configpath := "."
	switch env {
	case "production":
		configName = "config.local"
	case "test":
		configName = "config.test"
		configpath = "../../"
	}
	viper.SetConfigName(configName)
	viper.SetConfigType("yaml")
	viper.AddConfigPath(configpath)
	if err := viper.ReadInConfig(); err != nil {
		panic("failed to read config")
	}
}
