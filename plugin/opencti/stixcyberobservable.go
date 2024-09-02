package opencti

import "time"

type StixCyberObservable struct {
	Typename              string        `json:"__typename"`
	ID                    string        `json:"id"`
	StandardID            string        `json:"standard_id"`
	EntityType            string        `json:"entity_type"`
	ObservableValue       string        `json:"observable_value"`
	IsStixCyberObservable string        `json:"__isStixCyberObservable"`
	XOpenctiStixIDs       []interface{} `json:"x_opencti_stix_ids"`
	SpecVersion           string        `json:"spec_version"`
	CreatedAt             time.Time     `json:"created_at"`
	UpdatedAt             time.Time     `json:"updated_at"`
	CreatedBy             interface{}   `json:"createdBy"`
	Creators              []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"creators"`
	ObjectMarking       []interface{} `json:"objectMarking"`
	ObjectLabel         []interface{} `json:"objectLabel"`
	XOpenctiScore       int           `json:"x_opencti_score"`
	XOpenctiDescription interface{}   `json:"x_opencti_description"`
	Value               string        `json:"value"`
	ParentTypes         []string      `json:"parent_types"`
	Indicators          struct {
		Edges    []interface{} `json:"edges"`
		PageInfo struct {
			EndCursor   string `json:"endCursor"`
			HasNextPage bool   `json:"hasNextPage"`
		} `json:"pageInfo"`
	} `json:"indicators"`
	IsStixCoreObject string `json:"__isStixCoreObject"`
	ImportFiles      struct {
		Edges    []interface{} `json:"edges"`
		PageInfo struct {
			EndCursor   string `json:"endCursor"`
			HasNextPage bool   `json:"hasNextPage"`
		} `json:"pageInfo"`
	} `json:"importFiles"`
	ExportFiles struct {
		Edges    []interface{} `json:"edges"`
		PageInfo struct {
			EndCursor   string `json:"endCursor"`
			HasNextPage bool   `json:"hasNextPage"`
		} `json:"pageInfo"`
	} `json:"exportFiles"`
	ExternalReferences struct {
		Edges []interface{} `json:"edges"`
	} `json:"externalReferences"`
	PendingFiles struct {
		Edges    []interface{} `json:"edges"`
		PageInfo struct {
			EndCursor   string `json:"endCursor"`
			HasNextPage bool   `json:"hasNextPage"`
		} `json:"pageInfo"`
	} `json:"pendingFiles"`
}
