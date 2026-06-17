package cli

import (
	snap "github.com/kernelstub/cognitor/internal/snapshot"
	"github.com/spf13/cobra"
)

func newSnapshotCommand(streams ioStreams, configPath *string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "snapshot",
		Short: "Create or prepare snapshot directories",
	}
	cmd.AddCommand(newSnapshotCreateCommand(streams, configPath))
	return cmd
}

func newSnapshotCreateCommand(streams ioStreams, configPath *string) *cobra.Command {
	var name, path, source string
	var force bool
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a scan-ready snapshot directory",
		RunE: func(cmd *cobra.Command, args []string) error {
			if _, err := loadConfig(*configPath); err != nil {
				return err
			}
			result, err := snap.Create(cmd.Context(), snap.CreateOptions{Name: name, Path: path, Source: source, Force: force})
			if err != nil {
				return err
			}
			statusf(streams.stdout, statusSuccess, "created snapshot %s: copied=%d created=%d skipped=%d", result.Path, result.CopiedFiles, result.CreatedFiles, result.SkippedFiles)
			return nil
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "snapshot name")
	cmd.Flags().StringVar(&path, "path", "", "snapshot directory to create")
	cmd.Flags().StringVar(&source, "source", "", "optional source directory to copy binaries and sidecars from")
	cmd.Flags().BoolVar(&force, "force", false, "overwrite existing generated files and copied inputs")
	_ = cmd.MarkFlagRequired("name")
	_ = cmd.MarkFlagRequired("path")
	return cmd
}
