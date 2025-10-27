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
	cfgFile     string
	verbose     bool
	debug       bool
	outputFormat string
	metricsPort int
)

func newRootCmd(ctx context.Context, logger *logging.Logger) *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   "aegis",
		Short: "Aegis - High-Performance Network Scanner",
		Long: `Aegis is an ultra-high-throughput reconnaissance engine designed for
massive concurrent scans, host discovery, port enumeration, service fingerprinting,
and vulnerability mapping with forensic-grade output.`,
		Version: "2.0.0",
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			if debug {
				logger.SetMinLevel(logging.SeverityDebug)
			} else if verbose {
				logger.SetMinLevel(logging.SeverityInfo)
			}
		},
	}

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.aegis.yaml)")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "verbose output")
	rootCmd.PersistentFlags().BoolVar(&debug, "debug", false, "debug output")
	rootCmd.PersistentFlags().StringVarP(&outputFormat, "output", "o", "json", "output format (json|ndjson|sarif|csv|text)")
	rootCmd.PersistentFlags().IntVar(&metricsPort, "metrics-port", 9090, "Prometheus metrics port")

	cobra.OnInitialize(initConfig)

	rootCmd.AddCommand(newScanCmd(ctx, logger))
	rootCmd.AddCommand(newDiscoverCmd(ctx, logger))
	rootCmd.AddCommand(newWatchCmd(ctx, logger))
	rootCmd.AddCommand(newVersionCmd())
	rootCmd.AddCommand(newMetricsCmd(ctx, logger))

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
		viper.SetConfigName(".aegis")
	}

	viper.SetEnvPrefix("AEGIS")
	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err == nil {
		fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
	}
}
