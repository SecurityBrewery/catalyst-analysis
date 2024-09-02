package config

import (
	"context"
	"reflect"
	"testing"
)

func TestJSONProvider_Get(t *testing.T) {
	t.Parallel()

	type fields struct {
		m *JSONConfig
	}

	type args struct {
		plugin string
		key    string
	}

	tests := []struct {
		name    string
		fields  fields
		args    args
		want    string
		want1   bool
		wantErr bool
	}{
		{
			name: "Test JSONProvider Get",
			fields: fields{
				m: &JSONConfig{
					Services: map[string]*JSONServiceConfig{
						"test": {
							Plugin: "test",
							Config: map[string]string{
								"test": "test",
							},
						},
					},
				},
			},
			args: args{
				plugin: "test",
				key:    "test",
			},
			want:    "test",
			want1:   true,
			wantErr: false,
		},
		{
			name: "Test JSONProvider Get Not Found",
			fields: fields{
				m: &JSONConfig{},
			},
			args: args{
				plugin: "test",
				key:    "test",
			},
			want:    "",
			want1:   false,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctx := context.Background()

			j := &JSONProvider{
				m: tt.fields.m,
			}

			got, got1, err := j.Get(ctx, tt.args.plugin, tt.args.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("Get() error = %v, wantErr %v", err, tt.wantErr)

				return
			}

			if got != tt.want {
				t.Errorf("Get() got = %v, want %v", got, tt.want)
			}

			if got1 != tt.want1 {
				t.Errorf("Get() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func TestNewJSONProvider(t *testing.T) {
	t.Parallel()

	type args struct {
		data []byte
	}

	tests := []struct {
		name    string
		args    args
		want    *JSONProvider
		wantErr bool
	}{
		{
			name: "Test NewJSONProvider",
			args: args{
				data: []byte(`{"services":{"test": {"plugin": "test", "config": {}}}}`),
			},
			want: &JSONProvider{
				m: &JSONConfig{
					Services: map[string]*JSONServiceConfig{
						"test": {
							Plugin: "test",
							Config: map[string]string{},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "Test NewJSONProvider Error",
			args: args{
				data: []byte(`{`),
			},
			want:    nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := NewJSONProvider(tt.args.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewJSONProvider() error = %v, wantErr %v", err, tt.wantErr)

				return
			}

			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewJSONProvider() got = %v, want %v", got, tt.want)
			}
		})
	}
}
