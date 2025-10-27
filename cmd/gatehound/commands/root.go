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
)

func newRootCmd(ctx context.Context, logger *logging.Logger) *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   "gatehound",
		Short: "Gatehound - Passive Network Defense & IP-Locating System",
		Long: `Gatehound is an always-on passive monitoring system that detects unknown
devices, fingerprints network entities, collects router forensics, enriches IP
data with geolocation/ASN/WHOIS, and generates comprehensive PDF incident reports
with full forensic metadata and signed chain-of-custody.`,
		Version: "1.0.0",
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			if debug {
				logger.SetMinLevel(logging.SeverityDebug)
			} else if verbose {
				logger.SetMinLevel(logging.SeverityInfo)
			}
		},
	}

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.gatehound.yaml)")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "verbose output")
	rootCmd.PersistentFlags().BoolVar(&debug, "debug", false, "debug output")
	rootCmd.PersistentFlags().StringVarP(&outputFormat, "output", "o", "json", "output format (json|ndjson|text)")
	rootCmd.PersistentFlags().IntVar(&metricsPort, "metrics-port", 9091, "Prometheus metrics port")

	cobra.OnInitialize(initConfig)

	rootCmd.AddCommand(newStartCmd(ctx, logger))
	rootCmd.AddCommand(newProbeCmd(ctx, logger))
	rootCmd.AddCommand(newPolicyCmd(ctx, logger))
	rootCmd.AddCommand(newListCmd(ctx, logger))
	rootCmd.AddCommand(newReportCmd(ctx, logger))
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
		viper.SetConfigName(".gatehound")
	}

	viper.SetEnvPrefix("GATEHOUND")
	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err == nil {
		fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
	}
}
