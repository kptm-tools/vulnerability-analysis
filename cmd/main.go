package main

import (
	"fmt"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	cmmn "github.com/kptm-tools/common/common/pkg/events"
	"github.com/kptm-tools/vulnerability-analysis/pkg/config"
	"github.com/kptm-tools/vulnerability-analysis/pkg/events"
	"github.com/kptm-tools/vulnerability-analysis/pkg/handlers"
	"github.com/kptm-tools/vulnerability-analysis/pkg/services"
	"github.com/lmittmann/tint"
)

func main() {
	fmt.Println("Hello Vulnerability Analysis!")
	c := config.LoadConfig()

	// Logger
	slog.SetDefault(slog.New(tint.NewHandler(os.Stdout, &tint.Options{
		Level:      slog.LevelDebug,
		TimeFormat: time.Stamp,
	})))

	// Events
	eventBus, err := cmmn.NewNatsEventBus(c.GetNatsConnStr())
	if err != nil {
		log.Fatalf("Error creating Event Bus: %s\n", err.Error())
	}

	// Services
	nmapService := services.NewNmapService()

	// Handlers
	nmapHandler := handlers.NewNmapHandler(nmapService)

	err = eventBus.Init(func() error {
		if err := events.SubscribeToScanStarted(eventBus, nmapHandler); err != nil {
			return err
		}
		if err := events.SubscribeToScanCancelled(eventBus); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		log.Fatalf("Failed to initialize Event Bus: %s\n", err.Error())
	}
	waitForShutdown()
}

func waitForShutdown() {
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	// Block until signal is received
	<-stop
	log.Println("Shutting down gracefully...")

}
