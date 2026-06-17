package cli

import (
	"io"

	"github.com/spf13/cobra"
)

const Version = "1.0.2"

type ioStreams struct {
	stdout io.Writer
	stderr io.Writer
}

func NewRoot(stdout io.Writer, stderr io.Writer) *cobra.Command {
	streams := ioStreams{stdout: stdout, stderr: stderr}
	var configPath string
	cmd := &cobra.Command{
		Use:           "cognitor",
		Short:         "Patch Tuesday semantic diff platform for defensive Windows vulnerability research",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	cmd.PersistentFlags().StringVar(&configPath, "config", "", "config file path")
	cmd.AddCommand(newAnalyzeCommand(streams, &configPath))
	cmd.AddCommand(newSnapshotCommand(streams, &configPath))
	cmd.AddCommand(newScanCommand(streams, &configPath))
	cmd.AddCommand(newDiffCommand(streams, &configPath))
	cmd.AddCommand(newReportCommand(streams, &configPath))
	cmd.AddCommand(newGraphCommand(streams, &configPath))
	cmd.AddCommand(newLabCommand(streams, &configPath))
	cmd.AddCommand(newRulesCommand(streams))
	cmd.AddCommand(newVersionCommand(streams))
	return cmd
}
