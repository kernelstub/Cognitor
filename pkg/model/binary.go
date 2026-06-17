package model

type Binary struct {
	ID         string     `json:"id"`
	SnapshotID string     `json:"snapshot_id"`
	Path       string     `json:"path"`
	Name       string     `json:"name"`
	Kind       string     `json:"kind"`
	SHA256     string     `json:"sha256"`
	Size       int64      `json:"size"`
	Version    string     `json:"version"`
	Signer     string     `json:"signer"`
	Imports    []string   `json:"imports"`
	Exports    []string   `json:"exports"`
	Sections   []Section  `json:"sections"`
	Strings    []string   `json:"strings"`
	Functions  []Function `json:"functions"`
	IOCTLs     []IOCTL    `json:"ioctls,omitempty"`
	Manifest   string     `json:"manifest"`
}

type IOCTL struct {
	Code         string   `json:"code"`
	Name         string   `json:"name,omitempty"`
	Device       string   `json:"device,omitempty"`
	DeviceType   string   `json:"device_type,omitempty"`
	Method       string   `json:"method,omitempty"`
	Access       string   `json:"access,omitempty"`
	Function     string   `json:"function,omitempty"`
	Handlers     []string `json:"handlers,omitempty"`
	Reachability string   `json:"reachability,omitempty"`
	Source       string   `json:"source,omitempty"`
	RiskSignals  []string `json:"risk_signals,omitempty"`
}

type Artifact struct {
	ID         string   `json:"id"`
	SnapshotID string   `json:"snapshot_id"`
	Path       string   `json:"path"`
	Name       string   `json:"name"`
	Kind       string   `json:"kind"`
	SHA256     string   `json:"sha256"`
	Size       int64    `json:"size"`
	Strings    []string `json:"strings"`
}

type Section struct {
	Name string `json:"name"`
	Size int64  `json:"size"`
}
