package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/aegis-sentinel/aegis-suite/cmd/aegis/commands"
	"github.com/aegis-sentinel/aegis-suite/internal/common/logging"
)

func main() {
	logger := logging.Initialize("aegis")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		logger.Info("Received interrupt signal, shutting down gracefully...")
		cancel()
	}()

	if err := commands.Execute(ctx, logger); err != nil {
		logger.Error("Command execution failed", logging.WithError(err))
		os.Exit(1)
	}
}
