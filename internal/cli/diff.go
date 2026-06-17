package cli

import (
	sem "github.com/kernelstub/cognitor/internal/diff"
	"github.com/kernelstub/cognitor/internal/graph"
	"github.com/kernelstub/cognitor/internal/store"
	"github.com/spf13/cobra"
)

func newDiffCommand(streams ioStreams, configPath *string) *cobra.Command {
	var oldDB, newDB, out string
	cmd := &cobra.Command{
		Use:   "diff",
		Short: "Compare two snapshot databases and store defensive findings",
		RunE: func(cmd *cobra.Command, args []string) error {
			if _, err := loadConfig(*configPath); err != nil {
				return err
			}
			oldStore, err := store.Open(oldDB)
			if err != nil {
				return err
			}
			defer oldStore.Close()
			newStore, err := store.Open(newDB)
			if err != nil {
				return err
			}
			defer newStore.Close()
			oldSnapshot, err := oldStore.LoadSnapshot(cmd.Context())
			if err != nil {
				return err
			}
			newSnapshot, err := newStore.LoadSnapshot(cmd.Context())
			if err != nil {
				return err
			}
			findings := sem.Analyze(cmd.Context(), oldSnapshot, newSnapshot)
			changes := sem.SummarizeChanges(oldSnapshot, newSnapshot)
			outStore, err := store.Open(out)
			if err != nil {
				return err
			}
			defer outStore.Close()
			if err := outStore.SaveFindings(cmd.Context(), findings); err != nil {
				return err
			}
			if err := outStore.SaveChangeSummary(cmd.Context(), changes); err != nil {
				return err
			}
			if err := outStore.SaveGraph(cmd.Context(), graph.Build(newSnapshot, findings)); err != nil {
				return err
			}
			statusf(streams.stdout, statusSuccess, "diffed %d findings and %d changed binaries -> %s", len(findings), len(changes.ModifiedBinaries), out)
			return nil
		},
	}
	cmd.Flags().StringVar(&oldDB, "old", "", "old snapshot database")
	cmd.Flags().StringVar(&newDB, "new", "", "new snapshot database")
	cmd.Flags().StringVar(&out, "out", "", "findings database")
	_ = cmd.MarkFlagRequired("old")
	_ = cmd.MarkFlagRequired("new")
	_ = cmd.MarkFlagRequired("out")
	return cmd
}
