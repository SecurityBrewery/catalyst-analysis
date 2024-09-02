package config

import "context"

type Provider interface {
	Config(ctx context.Context) (*Config, error)
	Get(ctx context.Context, service, key string) (string, bool, error)
}

type Config struct {
	Services []*ServiceConfig
}

type ServiceConfig struct {
	ID     string
	Plugin string
}
