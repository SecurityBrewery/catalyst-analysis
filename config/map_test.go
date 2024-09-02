package config

import (
	"context"
	"testing"
)

func TestMapProvider(t *testing.T) {
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
			name: "Test MapProvider Get",
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
			name: "Test MapProvider Get Not Found",
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

			s := NewMapProvider(tt.fields.m)

			got, got1, err := s.Get(ctx, tt.args.plugin, tt.args.key)
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
