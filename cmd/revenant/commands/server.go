package commands

import (
	"context"
	"fmt"
	"time"

	"github.com/aegis-sentinel/aegis-suite/internal/common/logging"
	"github.com/aegis-sentinel/aegis-suite/internal/common/store"
	"github.com/aegis-sentinel/aegis-suite/internal/common/telemetry"
	"github.com/aegis-sentinel/aegis-suite/internal/revenant/actions"
	"github.com/aegis-sentinel/aegis-suite/internal/revenant/api"
	"github.com/aegis-sentinel/aegis-suite/internal/revenant/authz"
	"github.com/aegis-sentinel/aegis-suite/internal/revenant/orchestrator"
	"github.com/aegis-sentinel/aegis-suite/internal/revenant/playbooks"
	"github.com/spf13/cobra"
)

type serverOptions struct {
	dbPath string
}

func newServerCmd(ctx context.Context, logger *logging.Logger) *cobra.Command {
	opts := &serverOptions{}

	cmd := &cobra.Command{
		Use:   "server",
		Short: "Start Revenant API server",
		Long: `Start the Revenant orchestration API server.

The server provides:
- REST API for task submission and management
- Task approval workflows
- Real-time task status monitoring
- Metrics and health endpoints

The API will be available at http://localhost:8080 by default.

Examples:
  revenant server
  revenant server --api-port=9000
  revenant server --db-path=/var/lib/revenant/data.db`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runServer(ctx, logger, opts)
		},
	}

	cmd.Flags().StringVar(&opts.dbPath, "db-path", "./data/revenant.db", "database path")

	return cmd
}

func runServer(ctx context.Context, logger *logging.Logger, opts *serverOptions) error {
	logger.Info("Starting Revenant orchestration server",
		logging.WithAction("start"),
	)

	metrics := telemetry.Global()
	go func() {
		addr := fmt.Sprintf(":%d", metricsPort)
		logger.Info(fmt.Sprintf("Starting metrics server on %s", addr))
		if err := metrics.StartMetricsServer(addr); err != nil {
			logger.Error("Metrics server failed", logging.WithError(err))
		}
	}()

	st, err := store.Open(opts.dbPath)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	defer st.Close()

	playbookExecutor := playbooks.NewPlaybookExecutor(logger)
	playbookExecutor.RegisterAction("containment", actions.NewContainmentAction(logger))
	playbookExecutor.RegisterAction("command", actions.NewCommandAction(logger, false))

	engineConfig := &orchestrator.EngineConfig{
		Workers:    10,
		MaxRetries: 3,
		RetryDelay: 5 * time.Second,
		QueueSize:  1000,
	}

	engine := orchestrator.NewEngine(engineConfig, logger, metrics, playbookExecutor)
	engine.Start()
	defer engine.Stop()

	rbac := authz.NewRBAC()

	adminUser := &authz.User{
		ID:       "admin",
		Username: "admin",
		Roles:    []authz.Role{authz.RoleAdmin},
	}
	rbac.AddUser(adminUser)

	apiAddr := fmt.Sprintf(":%d", apiPort)
	apiServer := api.NewServer(apiAddr, logger, engine, rbac)

	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Println("               REVENANT ORCHESTRATION SERVER")
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Printf("API Server:     http://localhost%s\n", apiAddr)
	fmt.Printf("Metrics:        http://localhost:%d/metrics\n", metricsPort)
	fmt.Printf("Health:         http://localhost%s/healthz\n", apiAddr)
	fmt.Printf("Workers:        %d\n", engineConfig.Workers)
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Println("\nServer is ready to accept requests...")

	errChan := make(chan error, 1)
	go func() {
		if err := apiServer.Start(); err != nil {
			errChan <- err
		}
	}()

	select {
	case <-ctx.Done():
		logger.Info("Shutting down server")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		return apiServer.Stop(shutdownCtx)
	case err := <-errChan:
		return fmt.Errorf("server error: %w", err)
	}
}
