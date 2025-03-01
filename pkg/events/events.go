package events

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"

	"github.com/google/uuid"
	"github.com/kptm-tools/common/common/pkg/enums"
	cmmn "github.com/kptm-tools/common/common/pkg/events"
	"github.com/kptm-tools/common/common/pkg/results/tools"
	"github.com/kptm-tools/vulnerability-analysis/pkg/interfaces"
	"github.com/nats-io/nats.go"
)

// contextMap is a map used for accessing cancel functions for scans
// keys are scanID's, values are cancel functions
var contextMap sync.Map

func SubscribeToScanStarted(
	bus cmmn.EventBus,
	nmapHandler interfaces.INmapHandler,
) error {
	bus.Subscribe(string(enums.ScanStartedEventSubject), func(msg *nats.Msg) {

		go func(msg *nats.Msg) {

			slog.Info("Received ScanStartedEvent")
			// 1. Parse the message payload
			var payload cmmn.ScanStartedEvent

			if err := json.Unmarshal(msg.Data, &payload); err != nil {
				slog.Error("Received invalid JSON payload", slog.Any("payload", msg.Data))
				failedPayload := cmmn.NewScanFailedEvent(payload.ScanID, fmt.Errorf("invalid JSON payload: %w", err).Error())
				msg, err := json.Marshal(failedPayload)
				if err != nil {
					slog.Error("failed to marshal scan failed payload", slog.Any("error", err))
				}
				bus.Publish(string(enums.ScanFailedEventSubject), msg)

				return
			}

			// Cancellation context
			ctx, cancel := context.WithCancel(context.Background())
			contextMap.Store(payload.ScanID, cancel)
			defer func() {
				contextMap.Delete(payload.ScanID)
				cancel()
			}()

			slog.Debug("Received payload", slog.Any("payload", payload))
			// 2. Call our handlers for each tool
			c := nmapHandler.RunScan(ctx, payload)

			for result := range c {
				if result.Err != nil {
					slog.Warn("Encountered error running Nmap Scan", slog.Any("error", result.Err))
				}
				// 3. Publish the result
				if err := processNmapResult(payload.ScanID, result, bus); err != nil {
					slog.Error("Failed to process NmapResult", slog.Any("error", err))
					failedPayload := cmmn.NewScanFailedEvent(payload.ScanID, fmt.Errorf("failed to process NmapResult: %w", err).Error())
					msg, err := json.Marshal(failedPayload)
					if err != nil {
						slog.Error("failed to marshal scan failed payload", slog.Any("error", err))
					}
					bus.Publish(string(enums.ScanFailedEventSubject), msg)
				}

			}
			slog.Info("Finished analyzing vulnerabilities", slog.String("scanID", payload.ScanID.String()))

		}(msg)
	})

	return nil
}

func SubscribeToScanCancelled(bus cmmn.EventBus) error {
	bus.Subscribe(string(enums.ScanCancelledEventSubject), func(msg *nats.Msg) {
		go func(msg *nats.Msg) {

			slog.Info("Received ScanCancelledEvent")
			// 1. Parse the message payload
			var payload cmmn.ScanCancelledEvent
			if err := json.Unmarshal(msg.Data, &payload); err != nil {
				slog.Error("Received invalid JSON payload", slog.Any("payload", msg.Data))
				// 1.1 Publish scan cancelled failed?
				failedPayload := cmmn.NewScanFailedEvent(payload.ScanID, fmt.Errorf("invalid JSON payload: %w", err).Error())
				msg, err := json.Marshal(failedPayload)
				if err != nil {
					slog.Error("Failed to marshal scan failed payload", slog.Any("error", err))
				}
				bus.Publish(string(enums.ScanFailedEventSubject), msg)
				return
			}

			slog.Debug("Received payload", slog.Any("payload", payload))
			slog.Info("Cancelling scan", slog.String("scanID", payload.ScanID.String()))
			if cancelFunc, ok := contextMap.Load(payload.ScanID); ok {
				cancelFunc.(context.CancelFunc)() // Cancel the context
				contextMap.Delete(payload.ScanID)
				slog.Info("Scan successfully cancelled", slog.String("scanID", payload.ScanID.String()))
			} else {
				slog.Warn("No active scan found for ScanID", slog.String("scanID", payload.ScanID.String()))
			}
		}(msg)
	})
	return nil
}

func processNmapResult(scanID uuid.UUID, result tools.ToolResult, bus cmmn.EventBus) error {
	subject := enums.NmapEventSubject

	slog.Info("Publishing service result", slog.String("subject", string(subject)))

	factory := cmmn.ToolEventFactory{}

	payload, err := factory.BuildEvent(scanID, result)
	if err != nil {
		return fmt.Errorf("failed to build event: %w", err)
	}

	if err := bus.Publish(string(subject), payload); err != nil {
		return fmt.Errorf("failed to publish to subject %s: %w", string(subject), err)
	}

	return nil

}
