package cli

import (
	"fmt"
	"os"

	rep "github.com/kernelstub/cognitor/internal/report"
	"github.com/kernelstub/cognitor/internal/store"
	"github.com/spf13/cobra"
)

func newReportCommand(streams ioStreams, configPath *string) *cobra.Command {
	var dbPath, format, out string
	cmd := &cobra.Command{
		Use:   "report",
		Short: "Generate JSON, SARIF, CSV, or Markdown reports",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig(*configPath)
			if err != nil {
				return err
			}
			if format == "" {
				format = cfg.OutputFormat
			}
			db, err := store.Open(dbPath)
			if err != nil {
				return err
			}
			defer db.Close()
			findings, err := db.LoadFindings(cmd.Context())
			if err != nil {
				return err
			}
			graph, err := db.LoadGraph(cmd.Context())
			if err != nil {
				return err
			}
			changes, err := db.LoadChangeSummary(cmd.Context())
			if err != nil {
				return err
			}
			report := rep.Build(findings, graph, changes)
			var data []byte
			switch format {
			case "json":
				data, err = rep.JSON(report)
			case "sarif":
				data, err = rep.SARIF(report)
			case "csv":
				data, err = rep.CSV(report)
			case "markdown":
				data, err = rep.Markdown(report)
			default:
				return fmt.Errorf("unsupported report format %q", format)
			}
			if err != nil {
				return err
			}
			if out == "" {
				_, err = streams.stdout.Write(data)
				return err
			}
			if err := os.WriteFile(out, data, 0o644); err != nil {
				return err
			}
			statusf(streams.stdout, statusSuccess, "wrote %s report -> %s", format, out)
			return nil
		},
	}
	cmd.Flags().StringVar(&dbPath, "db", "", "findings database")
	cmd.Flags().StringVar(&format, "format", "", "report format: markdown, json, sarif, csv")
	cmd.Flags().StringVar(&out, "out", "", "output file")
	_ = cmd.MarkFlagRequired("db")
	return cmd
}
