package main

import (
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/urfave/cli/v2"

	"github.com/SecurityBrewery/catalyst-analysis/analysis"
	"github.com/SecurityBrewery/catalyst-analysis/cmd/server/service"
	"github.com/SecurityBrewery/catalyst-analysis/config"
	"github.com/SecurityBrewery/catalyst-analysis/generated/api"
)

func main() {
	app := &cli.App{
		Name:  "catalyst-analysis",
		Usage: "Catalyst Analysis Server",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "config",
				Aliases: []string{"c"},
				Usage:   "config file",
				Value:   "config.json",
				Action: func(_ *cli.Context, v string) error {
					_, err := os.Stat(v)

					return err
				},
				EnvVars: []string{"CATALYST_ANALYSIS_CONFIG", "CONFIG"},
			},
			&cli.StringFlag{
				Name:    "host",
				Usage:   "host",
				Value:   "",
				EnvVars: []string{"CATALYST_ANALYSIS_HOST", "HOST"},
			},
			&cli.StringFlag{
				Name:    "port",
				Usage:   "port",
				Value:   "8080",
				EnvVars: []string{"CATALYST_ANALYSIS_PORT", "PORT"},
			},
		},
		Action: run,
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}

func run(c *cli.Context) error {
	configJSON, err := os.ReadFile(c.String("config"))
	if err != nil {
		return err
	}

	configProvider, err := config.NewJSONProvider(configJSON)
	if err != nil {
		return err
	}

	apiServer, err := api.NewServer(service.New(analysis.NewEngine(analysis.LoadPlugins(c.Context, configProvider))))
	if err != nil {
		return err
	}

	server := &http.Server{
		Addr:              net.JoinHostPort(c.String("host"), c.String("port")),
		Handler:           apiServer,
		ReadHeaderTimeout: 3 * time.Second,
	}

	return server.ListenAndServe()
}
