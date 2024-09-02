package github

import (
	"context"

	"github.com/google/go-github/v63/github"

	"github.com/SecurityBrewery/catalyst-analysis/config"
	"github.com/SecurityBrewery/catalyst-analysis/plugin"
)

var (
	_ plugin.Plugin    = &GitHub{}
	_ plugin.Connector = &GitHub{}
)

type GitHub struct {
	config config.Provider
}

func New(config config.Provider) *GitHub {
	return &GitHub{config: config}
}

func (g *GitHub) Info() plugin.Info {
	return plugin.Info{
		Name: "GitHub",
		ResourceTypes: []plugin.ResourceType{
			&Issue{g: g},
		},
	}
}

func (g *GitHub) Connect(ctx context.Context) error {
	client, err := g.client(ctx)
	if err != nil {
		return err
	}

	_, _, err = client.Users.Get(ctx, "")

	return err
}

func (g *GitHub) client(ctx context.Context) (*github.Client, error) {
	token, _, err := g.config.Get(ctx, "github", "token")
	if err != nil {
		return nil, err
	}

	return github.NewClient(nil).WithAuthToken(token), nil
}
