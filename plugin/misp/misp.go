package misp

import (
	"context"
	"errors"
	"io"
	"net/http"

	"github.com/SecurityBrewery/catalyst-analysis/config"
	"github.com/SecurityBrewery/catalyst-analysis/plugin"
)

var (
	_ plugin.Plugin    = &MISP{}
	_ plugin.Connector = &MISP{}
)

type MISP struct {
	url    string
	config config.Provider
}

func New(ctx context.Context, config config.Provider) (*MISP, error) {
	url, found, err := config.Get(ctx, "misp", "url")
	if err != nil {
		return nil, err
	}

	if !found {
		return nil, errors.New("misp url not found")
	}

	return &MISP{
		url:    url,
		config: config,
	}, nil
}

func (g *MISP) Info() plugin.Info {
	return plugin.Info{
		Name: "MISP",
		ResourceTypes: []plugin.ResourceType{
			&Event{g: g},
		},
	}
}

func (g *MISP) Connect(ctx context.Context) error {
	resp, err := g.request(ctx, http.MethodGet, g.url+"/events", nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return errors.New("misp connection failed")
	}

	return nil
}

func (g *MISP) request(ctx context.Context, method, url string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, err
	}

	key, found, err := g.config.Get(ctx, "misp", "key")
	if err != nil {
		return nil, err
	}

	if !found {
		return nil, errors.New("misp key not found")
	}

	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("Accept", "application/json")

	return http.DefaultClient.Do(req)
}
