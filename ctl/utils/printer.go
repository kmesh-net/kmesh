package utils

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"
	"sigs.k8s.io/yaml"
)

// PrintOutput checks if the global --output (-o) flag is set on the command.
// If it is set to "json" or "yaml", it marshals the data appropriately, prints it to stdout,
// and returns true (indicating to the caller that default table/text formatting can be skipped).
// If no output format is specified, it returns false.
func PrintOutput(cmd *cobra.Command, data interface{}) (bool, error) {
	outputFlag, err := cmd.Flags().GetString("output")
	if err != nil {
		// Flag might not be defined on some commands, default to normal output
		return false, nil
	}

	switch outputFlag {
	case "json":
		b, err := json.MarshalIndent(data, "", "  ")
		if err != nil {
			return false, fmt.Errorf("failed to marshal json: %w", err)
		}
		fmt.Println(string(b))
		return true, nil
	case "yaml", "yml":
		b, err := yaml.Marshal(data)
		if err != nil {
			return false, fmt.Errorf("failed to marshal yaml: %w", err)
		}
		fmt.Print(string(b)) // yaml.Marshal already appends a newline
		return true, nil
	case "":
		return false, nil
	default:
		// Unsupported output format, fallback to default or throw error
		return false, fmt.Errorf("unsupported output format: %s", outputFlag)
	}
}
