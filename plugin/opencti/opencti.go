package opencti

import (
	"context"
	"errors"
	"io"
	"net/http"

	"github.com/SecurityBrewery/catalyst-analysis/config"
	"github.com/SecurityBrewery/catalyst-analysis/plugin"
)

var (
	_ plugin.Plugin    = &OpenCTI{}
	_ plugin.Connector = &OpenCTI{}
)

type OpenCTI struct {
	url    string
	config config.Provider
}

func New(ctx context.Context, config config.Provider) (*OpenCTI, error) {
	url, found, err := config.Get(ctx, "opencti", "url")
	if err != nil {
		return nil, err
	}

	if !found {
		return nil, errors.New("opencti url not found")
	}

	return &OpenCTI{
		url:    url,
		config: config,
	}, nil
}

func (g *OpenCTI) Info() plugin.Info {
	return plugin.Info{
		Name: "OpenCTI",
		ResourceTypes: []plugin.ResourceType{
			&Object{g: g},
		},
	}
}

func (g *OpenCTI) Connect(ctx context.Context) error {
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

func (g *OpenCTI) request(ctx context.Context, method, url string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, err
	}

	key, found, err := g.config.Get(ctx, "opencti", "key")
	if err != nil {
		return nil, err
	}

	if !found {
		return nil, errors.New("opencti key not found")
	}

	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")

	return http.DefaultClient.Do(req)
}
