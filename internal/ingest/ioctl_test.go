package ingest

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestScanReadsIOCTLSidecar(t *testing.T) {
	root := t.TempDir()
	driver := filepath.Join(root, "bindflt.sys")
	if err := os.WriteFile(driver, []byte("fake driver bytes"), 0o644); err != nil {
		t.Fatal(err)
	}
	sidecar := `{
  "functions": [
    {
      "name": "DispatchDeviceControl",
      "ioctls": [
        {"code": "50", "handlers": ["DispatchDeviceControl"], "reachability": "noob"}
      ]
    }
  ],
  "ioctls": [
    {"code": "0x50", "device": "\\\\.\\bindflt"}
  ]
}`
	if err := os.WriteFile(driver+".analysis.json", []byte(sidecar), 0o644); err != nil {
		t.Fatal(err)
	}

	snapshot, err := Scan(context.Background(), Options{Name: "new", Path: root, Workers: 1, StringMinLength: 5})
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Binaries) != 1 {
		t.Fatalf("expected one binary, got %d", len(snapshot.Binaries))
	}
	if len(snapshot.Binaries[0].IOCTLs) != 1 {
		t.Fatalf("expected deduped ioctl, got %#v", snapshot.Binaries[0].IOCTLs)
	}
	ioctl := snapshot.Binaries[0].IOCTLs[0]
	if ioctl.Code != "0x50" {
		t.Fatalf("expected normalized code 0x50, got %q", ioctl.Code)
	}
	if ioctl.Reachability != "noob" {
		t.Fatalf("expected reachability to merge, got %#v", ioctl)
	}
}
