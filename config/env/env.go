package env

import (
	"os"

	"github.com/spf13/viper"
)

func Load() {
	env := os.Getenv("ENV")
	configName := "config"
	if env != "production" {
		configName = "config.local"
	}
	viper.SetConfigName(configName)
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")
	if err := viper.ReadInConfig(); err != nil {
		panic("failed to read config")
	}
}
