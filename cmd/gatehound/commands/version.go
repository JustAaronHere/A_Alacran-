package commands

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("Gatehound v1.0.0")
			fmt.Println("Passive Network Defense & IP-Locating System")
		},
	}
}
