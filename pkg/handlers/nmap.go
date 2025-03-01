package handlers

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/kptm-tools/common/common/pkg/enums"
	"github.com/kptm-tools/common/common/pkg/events"
	"github.com/kptm-tools/common/common/pkg/results/tools"
	"github.com/kptm-tools/common/common/pkg/utils"
	"github.com/kptm-tools/vulnerability-analysis/pkg/interfaces"
)

type NmapHandler struct {
	nmapService interfaces.INmapService
}

var _ interfaces.INmapHandler = (*NmapHandler)(nil)

func NewNmapHandler(nmapService interfaces.INmapService) *NmapHandler {
	return &NmapHandler{
		nmapService: nmapService,
	}
}

func (h *NmapHandler) RunScan(ctx context.Context, event events.ScanStartedEvent) <-chan tools.ToolResult {
	c := make(chan tools.ToolResult)

	go func() {
		defer close(c)

		target, err := utils.ValidateHostForTool(event.Target.Value, enums.ToolNmap)
		if err != nil {
			slog.Error("Error validating host for tool: %w", slog.Any("error", err))
			c <- tools.ToolResult{
				Tool:   enums.ToolNmap,
				Result: &tools.NmapResult{},
				Err: &tools.ToolError{
					Code:    enums.ValidationError,
					Message: fmt.Sprintf("invalid target: %s", event.Target.Value),
				},
				Timestamp: time.Now().UTC(),
			}
			return
		}

		// Run scan
		result, err := h.nmapService.RunScan(ctx, target)

		// Check for context cancellation
		if ctx.Err() != nil {
			if ctx.Err() == context.Canceled {
				slog.Warn("Scan was canceled",
					slog.String("scanID", event.ScanID.String()),
					slog.Any("target", event.Target),
				)
			}
			return
		}

		// Handle scan errors
		if err != nil {
			slog.Error("Error running nmap scan",
				slog.String("scanID", event.ScanID.String()),
				slog.Any("error", err))
		}

		// Log results
		slog.Info("Nmap scan summary",
			slog.Any("target", event.Target),
			slog.Any("summary", result.Result))

		// Send scan results
		c <- result
	}()

	return c

}
