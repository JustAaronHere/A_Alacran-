package commands

import (
	"context"
	"fmt"
	"os"

	"github.com/aegis-sentinel/aegis-suite/internal/common/logging"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	cfgFile      string
	verbose      bool
	debug        bool
	outputFormat string
	metricsPort  int
	apiPort      int
)

func newRootCmd(ctx context.Context, logger *logging.Logger) *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   "revenant",
		Short: "Revenant - Active Response & Remediation Orchestrator",
		Long: `Revenant is an active response orchestrator that performs safe verification,
automated containment, remediation playbooks, and generates signed forensic reports.

Features:
- Sandbox verification of exploits and suspicious behavior
- Automated containment (NAC, firewall, EDR quarantine)
- Idempotent remediation playbooks with rollback support
- RBAC-based approval workflows
- Signed audit trails and remediation reports
- REST/gRPC API for integration`,
		Version: "1.0.0",
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			if debug {
				logger.SetMinLevel(logging.SeverityDebug)
			} else if verbose {
				logger.SetMinLevel(logging.SeverityInfo)
			}
		},
	}

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.revenant.yaml)")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "verbose output")
	rootCmd.PersistentFlags().BoolVar(&debug, "debug", false, "debug output")
	rootCmd.PersistentFlags().StringVarP(&outputFormat, "output", "o", "json", "output format (json|text)")
	rootCmd.PersistentFlags().IntVar(&metricsPort, "metrics-port", 9092, "Prometheus metrics port")
	rootCmd.PersistentFlags().IntVar(&apiPort, "api-port", 8080, "REST API server port")

	cobra.OnInitialize(initConfig)

	rootCmd.AddCommand(newRunPlaybookCmd(ctx, logger))
	rootCmd.AddCommand(newSandboxVerifyCmd(ctx, logger))
	rootCmd.AddCommand(newTasksCmd(ctx, logger))
	rootCmd.AddCommand(newServerCmd(ctx, logger))
	rootCmd.AddCommand(newPlaybookCmd(ctx, logger))
	rootCmd.AddCommand(newVersionCmd())

	return rootCmd
}

func Execute(ctx context.Context, logger *logging.Logger) error {
	return newRootCmd(ctx, logger).ExecuteContext(ctx)
}

func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		home, err := os.UserHomeDir()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}

		viper.AddConfigPath(home)
		viper.AddConfigPath(".")
		viper.SetConfigType("yaml")
		viper.SetConfigName(".revenant")
	}

	viper.SetEnvPrefix("REVENANT")
	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err == nil {
		fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
	}
}
