package ignition

import (
	"encoding/json"
	"fmt"
	"os"

	ign3types "github.com/coreos/ignition/v2/config/v3_4/types"
)

func Load(fpath string) (ign3types.Config, error) {
	rawIgn, err := os.ReadFile(fpath)
	if err != nil {
		return ign3types.Config{}, fmt.Errorf("failed to load config set %s: %w", fpath, err)
	}

	return ParseAndConvertConfig(rawIgn)
}

func Save(fpath string, ign *ign3types.Config) error {
	rawIgn, err := json.Marshal(ign)
	if err != nil {
		return fmt.Errorf("failed to marshal config set: %w", err)
	}

	return os.WriteFile(fpath, rawIgn, 0644)
}

func EnsureExists(fpath string) error {
	if _, err := os.Stat(fpath); os.IsNotExist(err) {
		ign := ign3types.Config{
			Ignition: ign3types.Ignition{
				Version: ign3types.MaxVersion.String(),
			},
		}
		return Save(fpath, &ign)
	}
	return nil
}
