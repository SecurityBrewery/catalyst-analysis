package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/sjson"

	"github.com/SecurityBrewery/catalyst-analysis/analysis"
	"github.com/SecurityBrewery/catalyst-analysis/cmd/server/service"
	"github.com/SecurityBrewery/catalyst-analysis/generated/api"
	"github.com/SecurityBrewery/catalyst-analysis/plugin/attack"
	"github.com/SecurityBrewery/catalyst-analysis/plugin/vulnerability"
)

func TestServer_ServeHTTP(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		services []*analysis.Service
		request  *http.Request
		response *http.Response
		ignore   []string
	}{
		{
			name:     "No plugins",
			services: []*analysis.Service{},
			request:  httptest.NewRequest(http.MethodGet, "/services", nil),
			response: &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"application/json; charset=utf-8"}},
				Body:       httptestBody(t, map[string]any{"services": []any{}}),
			},
		},
		{
			name:     "Services",
			services: []*analysis.Service{{ID: "vulnerability", Plugin: vulnerability.New()}},
			request:  httptest.NewRequest(http.MethodGet, "/services", nil),
			response: &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"application/json; charset=utf-8"}},
				Body: httptestBody(t, map[string]any{
					"services": []any{
						map[string]any{
							"id":   "vulnerability",
							"type": "Vulnerability",
							"resource_types": []any{
								map[string]any{
									"id":                  "cve",
									"name":                "CVE",
									"enrichment_patterns": []any{`CVE-\d{4}-\d{4,}`},
									"attributes": []any{
										"assigner", "published", "updated",
									},
								},
							},
						},
					},
				}),
			},
		},
		{
			name:     "Resource",
			services: []*analysis.Service{{ID: "vulnerability", Plugin: vulnerability.New()}},
			request:  httptest.NewRequest(http.MethodGet, "/services/vulnerability/cve/CVE-2017-0145", nil),
			response: &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"application/json; charset=utf-8"}},
				Body: httptestBody(t, map[string]any{
					"service":     "vulnerability",
					"type":        "cve",
					"id":          "CVE-2017-0145",
					"name":        "CVE-2017-0145",
					"icon":        "Bug",
					"url":         "https://vulnerability.circl.lu/vuln/CVE-2017-0145",
					"description": "The SMBv1 server in Microsoft Windows Vista SP2; Windows Server 2008 SP2 and R2 SP1; Windows 7 SP1; Windows 8.1; Windows Server 2012 Gold and R2; Windows RT 8.1; and Windows 10 Gold, 1511, and 1607; and Windows Server 2016 allows remote attackers to execute arbitrary code via crafted packets, aka \"Windows SMB Remote Code Execution Vulnerability.\" This vulnerability is different from those described in CVE-2017-0143, CVE-2017-0144, CVE-2017-0146, and CVE-2017-0148.",
					"attributes": []any{
						map[string]any{
							"id":    "assigner",
							"name":  "Assigner",
							"icon":  "User",
							"value": "microsoft",
						},
						map[string]any{
							"id":    "published",
							"name":  "Published",
							"icon":  "Calendar",
							"value": "2017-03-17T00:00:00",
						},
						map[string]any{
							"id":   "updated",
							"name": "Updated",
							"icon": "Calendar",
							// "value": "2024-08-05T12:55:18.654Z", // This value is dynamic
						},
					},
				}),
			},
			ignore: []string{"attributes.2.value"},
		},
		{
			name:     "Attributes",
			services: []*analysis.Service{{ID: "vulnerability", Plugin: vulnerability.New()}},
			request:  httptest.NewRequest(http.MethodGet, "/services/vulnerability/cve/CVE-2017-0145/assigner", nil),
			response: &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"application/json; charset=utf-8"}},
				Body: httptestBody(t, map[string]any{
					"id":    "assigner",
					"name":  "Assigner",
					"icon":  "User",
					"value": "microsoft",
				}),
			},
		},
		{
			name:     "Enrich",
			services: []*analysis.Service{{ID: "vulnerability", Plugin: vulnerability.New()}},
			request:  httptest.NewRequest(http.MethodGet, "/enrich/vulnerability/cve?value=CVE-2017-0145", nil),
			response: &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"application/json; charset=utf-8"}},
				Body: httptestBody(t, map[string]any{
					"service":     "vulnerability",
					"type":        "cve",
					"id":          "CVE-2017-0145",
					"name":        "CVE-2017-0145",
					"icon":        "Bug",
					"url":         "https://vulnerability.circl.lu/vuln/CVE-2017-0145",
					"description": "The SMBv1 server in Microsoft Windows Vista SP2; Windows Server 2008 SP2 and R2 SP1; Windows 7 SP1; Windows 8.1; Windows Server 2012 Gold and R2; Windows RT 8.1; and Windows 10 Gold, 1511, and 1607; and Windows Server 2016 allows remote attackers to execute arbitrary code via crafted packets, aka \"Windows SMB Remote Code Execution Vulnerability.\" This vulnerability is different from those described in CVE-2017-0143, CVE-2017-0144, CVE-2017-0146, and CVE-2017-0148.",
					"attributes": []any{
						map[string]any{
							"id":    "assigner",
							"name":  "Assigner",
							"icon":  "User",
							"value": "microsoft",
						},
						map[string]any{
							"id":    "published",
							"name":  "Published",
							"icon":  "Calendar",
							"value": "2017-03-17T00:00:00",
						},
						map[string]any{
							"id":   "updated",
							"name": "Updated",
							"icon": "Calendar",
							// "value": "2024-08-05T12:55:18.654Z", // This value is dynamic
						},
					},
				}),
			},
			ignore: []string{"attributes.2.value"},
		},
		{
			name:     "Fuzzy Enrich",
			services: []*analysis.Service{{ID: "vulnerability", Plugin: vulnerability.New()}},
			request:  httptest.NewRequest(http.MethodGet, "/enrich?value=CVE-2017-0145", nil),
			response: &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"application/json; charset=utf-8"}},
				Body: httptestBody(t, map[string]any{
					"resources": []any{
						map[string]any{
							"service":     "vulnerability",
							"type":        "cve",
							"id":          "CVE-2017-0145",
							"name":        "CVE-2017-0145",
							"icon":        "Bug",
							"url":         "https://vulnerability.circl.lu/vuln/CVE-2017-0145",
							"description": "The SMBv1 server in Microsoft Windows Vista SP2; Windows Server 2008 SP2 and R2 SP1; Windows 7 SP1; Windows 8.1; Windows Server 2012 Gold and R2; Windows RT 8.1; and Windows 10 Gold, 1511, and 1607; and Windows Server 2016 allows remote attackers to execute arbitrary code via crafted packets, aka \"Windows SMB Remote Code Execution Vulnerability.\" This vulnerability is different from those described in CVE-2017-0143, CVE-2017-0144, CVE-2017-0146, and CVE-2017-0148.",
							"attributes": []any{
								map[string]any{
									"id":    "assigner",
									"name":  "Assigner",
									"icon":  "User",
									"value": "microsoft",
								},
								map[string]any{
									"id":    "published",
									"name":  "Published",
									"icon":  "Calendar",
									"value": "2017-03-17T00:00:00",
								},
								map[string]any{
									"id":   "updated",
									"name": "Updated",
									"icon": "Calendar",
									// "value": "2024-08-05T12:55:18.654Z", // This value is dynamic
								},
							},
						},
					},
				}),
			},
			ignore: []string{"resources.0.attributes.2.value"},
		},
		{
			name: "Fuzzy Enrich 2",
			services: []*analysis.Service{
				{ID: "attack", Plugin: attack.New()},
			},
			request: httptest.NewRequest(http.MethodGet, "/enrich?value=TA0010", nil),
			response: &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"application/json; charset=utf-8"}},
				Body: httptestBody(t, map[string]any{
					"resources": []any{
						map[string]any{
							"service":     "attack",
							"type":        "tactic",
							"id":          "TA0010",
							"name":        "TA0010 Exfiltration",
							"icon":        "Shield",
							"url":         "https://attack.mitre.org/tactics/TA0010",
							"description": "The adversary is trying to steal data.\n\nExfiltration consists of techniques that adversaries may use to steal data from your network. Once they’ve collected data, adversaries often package it to avoid detection while removing it. This can include compression and encryption. Techniques for getting data out of a target network typically include transferring it over their command and control channel or an alternate channel and may also include putting size limits on the transmission.",
							"attributes":  []any{},
						},
					},
				}),
			},
			ignore: []string{"resources.0.attributes.2.value"},
		},
		{
			name: "Suggest",
			services: []*analysis.Service{
				{ID: "vulnerability", Plugin: vulnerability.New()},
				{ID: "attack", Plugin: attack.New()},
			},
			request: httptest.NewRequest(http.MethodGet, "/suggest?partial=Masquerading", nil),
			response: &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"application/json; charset=utf-8"}},
				Body: httptestBody(t, map[string]any{
					"resources": []any{
						map[string]any{
							"service":     "attack",
							"type":        "technique",
							"id":          "T1036",
							"name":        "T1036 Masquerading",
							"icon":        "Shield",
							"url":         "https://attack.mitre.org/techniques/T1036",
							"description": "Adversaries may attempt to manipulate features of their artifacts to make them appear legitimate or benign to users and/or security tools. Masquerading occurs when the name or location of an object, legitimate or malicious, is manipulated or abused for the sake of evading defenses and observation. This may include manipulating file metadata, tricking users into misidentifying the file type, and giving legitimate task or service names.\n\nRenaming abusable system utilities to evade security monitoring is also a form of [Masquerading](https://attack.mitre.org/techniques/T1036).(Citation: LOLBAS Main Site)",
							"attributes":  []any{},
						},
					},
				}),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			recorder := httptest.NewRecorder()

			s, err := api.NewServer(service.New(analysis.NewEngine(tt.services)))
			require.NoError(t, err)

			s.ServeHTTP(recorder, tt.request)

			assert.Equal(t, tt.response.StatusCode, recorder.Code)
			assert.Equal(t, tt.response.Header, recorder.Header())
			assertBodyEqual(t, tt.response.Body, recorder.Body, tt.ignore)
		})
	}
}

func httptestBody(t *testing.T, body any) io.ReadCloser {
	t.Helper()

	b, err := json.Marshal(body)
	require.NoError(t, err)

	return io.NopCloser(bytes.NewReader(b))
}

func assertBodyEqual(t *testing.T, expected, actual io.Reader, ignore []string) {
	t.Helper()

	expectedBytes, err := io.ReadAll(expected)
	require.NoError(t, err)

	actualBytes, err := io.ReadAll(actual)
	require.NoError(t, err)

	for _, i := range ignore {
		actualBytes, err = sjson.DeleteBytes(actualBytes, i)
		require.NoError(t, err)
	}

	assert.JSONEq(t, string(expectedBytes), string(actualBytes))
}
