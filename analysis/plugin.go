package analysis

import (
	"context"
	"errors"
	"log"
	"log/slog"
	"strings"

	"github.com/SecurityBrewery/catalyst-analysis/config"
	"github.com/SecurityBrewery/catalyst-analysis/plugin"
	"github.com/SecurityBrewery/catalyst-analysis/plugin/attack"
	"github.com/SecurityBrewery/catalyst-analysis/plugin/github"
	"github.com/SecurityBrewery/catalyst-analysis/plugin/misp"
	"github.com/SecurityBrewery/catalyst-analysis/plugin/opencti"
	"github.com/SecurityBrewery/catalyst-analysis/plugin/vulnerability"
)

func LoadPlugins(ctx context.Context, configProvider config.Provider) []*Service {
	config, err := configProvider.Config(ctx)
	if err != nil {
		log.Fatal(err)
	}

	var services []*Service

	for _, p := range config.Services {
		loadedPlugin, err := newPlugin(ctx, configProvider, p.Plugin)
		if err != nil {
			slog.ErrorContext(ctx, "failed to load plugin", "plugin", p.Plugin, "error", err.Error())

			continue
		}

		if connector, ok := loadedPlugin.(plugin.Connector); ok {
			if err := connector.Connect(ctx); err != nil {
				slog.WarnContext(ctx, "plugin disabled", "plugin", loadedPlugin.Info().Name, "error", err.Error())

				continue
			}
		}

		services = append(services, &Service{
			ID:     p.ID,
			Plugin: loadedPlugin,
		})
	}

	return services
}

func newPlugin(ctx context.Context, configProvider config.Provider, plugin string) (plugin.Plugin, error) {
	switch strings.ToLower(plugin) {
	case "attack":
		return attack.New(), nil
	case "github":
		return github.New(configProvider), nil
	case "misp":
		return misp.New(ctx, configProvider)
	case "opencti":
		return opencti.New(ctx, configProvider)
	case "vulnerability":
		return vulnerability.New(), nil
	default:
		return nil, errors.New("unknown plugin")
	}
}
