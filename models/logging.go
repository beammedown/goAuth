package utils

import (
	"os"

	"github.com/joho/godotenv"
	"github.com/rs/zerolog"
)

var Logger = zerolog.New(os.Stdout)

func SetupLogger() {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix

	Logger.Info().Msg("Starting services...")
	err := godotenv.Load()
	if err != nil {
		Logger.Error().Err(err).Msg("Error loading .env")
	}

}
