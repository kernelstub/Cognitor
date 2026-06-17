package config

import (
	"errors"
	"fmt"
)

func Validate(cfg Config) error {
	var errs []error
	if cfg.Workers < 1 {
		errs = append(errs, fmt.Errorf("workers must be greater than zero"))
	}
	if cfg.StringMinLength < 3 {
		errs = append(errs, fmt.Errorf("string_min_length must be at least three"))
	}
	switch cfg.OutputFormat {
	case "json", "markdown", "sarif", "csv":
	default:
		errs = append(errs, fmt.Errorf("output_format must be json, markdown, sarif, or csv"))
	}
	return errors.Join(errs...)
}
