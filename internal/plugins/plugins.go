package plugins

import (
	"fmt"
	"os"
	"path/filepath"
	"plugin"
	"runtime"

	"ligmashark/internal/types"
)

func LoadPlugins(dir string) ([]types.Plugin, error) {
	if runtime.GOOS == "windows" {
		return nil, nil
	}

	var loadedPlugins []types.Plugin

	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return loadedPlugins, nil
	}

	files, err := filepath.Glob(filepath.Join(dir, "*.so"))
	if err != nil {
		return nil, err
	}

	for _, file := range files {
		p, err := plugin.Open(file)
		if err != nil {
			fmt.Printf("Error loading plugin %s: %v\n", file, err)
			continue
		}

		symbol, err := p.Lookup("Plugin")
		if err != nil {
			fmt.Printf("Error looking up symbol 'Plugin' in %s: %v\n", file, err)
			continue
		}

		ptr, ok := symbol.(types.Plugin)
		if !ok {
			fmt.Printf("Symbol 'Plugin' in %s does not implement types.Plugin interface\n", file)
			continue
		}

		loadedPlugins = append(loadedPlugins, ptr)
		fmt.Printf("Loaded plugin: %s\n", ptr.Name())
	}

	return loadedPlugins, nil
}
