package model

type Function struct {
	ID              string   `json:"id"`
	BinaryID        string   `json:"binary_id"`
	Name            string   `json:"name"`
	NormalizedName  string   `json:"normalized_name"`
	Address         string   `json:"address"`
	BasicBlockCount int      `json:"basic_block_count"`
	Calls           []string `json:"calls"`
	Strings         []string `json:"strings"`
	Imports         []string `json:"imports"`
	Operations      []string `json:"operations"`
	IOCTLs          []IOCTL  `json:"ioctls,omitempty"`
}

type FunctionPair struct {
	Old        Function
	New        Function
	Similarity float64
	Reason     string
}
