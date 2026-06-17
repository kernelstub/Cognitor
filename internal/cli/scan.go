package cli

import (
	"github.com/kernelstub/cognitor/internal/ingest"
	"github.com/kernelstub/cognitor/internal/store"
	"github.com/spf13/cobra"
)

func newScanCommand(streams ioStreams, configPath *string) *cobra.Command {
	var name, path, out string
	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Scan a Windows build snapshot into SQLite",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig(*configPath)
			if err != nil {
				return err
			}
			snapshot, err := ingest.Scan(cmd.Context(), ingest.Options{Name: name, Path: path, Workers: cfg.Workers, StringMinLength: cfg.StringMinLength})
			if err != nil {
				return err
			}
			db, err := store.Open(out)
			if err != nil {
				return err
			}
			defer db.Close()
			if err := db.SaveSnapshot(cmd.Context(), snapshot); err != nil {
				return err
			}
			statusf(streams.stdout, statusSuccess, "scanned %s: %d binaries -> %s", name, len(snapshot.Binaries), out)
			return nil
		},
	}
	cmd.Flags().StringVar(&name, "snapshot", "", "snapshot name")
	cmd.Flags().StringVar(&path, "path", "", "snapshot directory")
	cmd.Flags().StringVar(&out, "out", "", "output SQLite database")
	_ = cmd.MarkFlagRequired("snapshot")
	_ = cmd.MarkFlagRequired("path")
	_ = cmd.MarkFlagRequired("out")
	return cmd
}
