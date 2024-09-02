package config

import (
	"context"
	"encoding/json"
)

type JSONConfig struct {
	Services map[string]*JSONServiceConfig `json:"services"`
}

type JSONServiceConfig struct {
	Plugin string            `json:"plugin"`
	Config map[string]string `json:"config"`
}

var _ Provider = &JSONProvider{}

type JSONProvider struct {
	m *JSONConfig
}

func NewJSONProvider(data []byte) (*JSONProvider, error) {
	var m *JSONConfig
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}

	return &JSONProvider{m: m}, nil
}

func (j *JSONProvider) Config(_ context.Context) (*Config, error) {
	var plugins []*ServiceConfig
	for name, config := range j.m.Services {
		plugins = append(plugins, &ServiceConfig{
			ID:     name,
			Plugin: config.Plugin,
		})
	}

	return &Config{
		Services: plugins,
	}, nil
}

func (j *JSONProvider) Get(_ context.Context, service, key string) (string, bool, error) {
	if n, ok := j.m.Services[service]; ok {
		if v, ok := n.Config[key]; ok {
			return v, true, nil
		}
	}

	return "", false, nil
}
