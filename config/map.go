package config

var _ Provider = &MapProvider{}

type MapProvider struct {
	*JSONProvider
}

func NewMapProvider(m *JSONConfig) *MapProvider {
	return &MapProvider{
		JSONProvider: &JSONProvider{
			m: m,
		},
	}
}
