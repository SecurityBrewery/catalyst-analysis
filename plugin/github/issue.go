package github

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	stripmd "github.com/writeas/go-strip-markdown"

	"github.com/SecurityBrewery/catalyst-analysis/plugin"
)

var _ plugin.Enricher = &Issue{}

type Issue struct {
	g *GitHub
}

func (i *Issue) Info() plugin.ResourceTypeInfo {
	return plugin.ResourceTypeInfo{
		ID:         "issue",
		Name:       "Issue",
		Attributes: []string{"status", "owner"},
		EnrichmentPatterns: []string{
			`https:\/\/github\.com\/[^/]+\/[^/]+\/issues\/\d+`,
		},
	}
}

func (i *Issue) Resource(ctx context.Context, id string) (*plugin.Resource, error) {
	id, err := url.PathUnescape(id)
	if err != nil {
		return nil, err
	}

	parts := strings.Split(id, "/")
	if len(parts) != 3 {
		return nil, errors.New("invalid github issue id")
	}

	org, repo, numberS := parts[0], parts[1], parts[2]

	number, err := strconv.Atoi(numberS)
	if err != nil {
		return nil, err
	}

	return i.issue(ctx, org, repo, number)
}

var gitHubIssueRegex = regexp.MustCompile(`https://github.com/([^/]+)/([^/]+)/issues/(\d+)`)

func (i *Issue) Enrich(ctx context.Context, value string) (*plugin.Resource, error) {
	matches := gitHubIssueRegex.FindStringSubmatch(value)
	if len(matches) != 4 {
		return nil, errors.New("invalid github issue url")
	}

	org, repo, numberS := matches[1], matches[2], matches[3]

	number, err := strconv.Atoi(numberS)
	if err != nil {
		return nil, err
	}

	return i.issue(ctx, org, repo, number)
}

func (i *Issue) issue(ctx context.Context, org, repo string, number int) (*plugin.Resource, error) {
	client, err := i.g.client(ctx)
	if err != nil {
		return nil, err
	}

	issue, _, err := client.Issues.Get(ctx, org, repo, number)
	if err != nil {
		return nil, err
	}

	owner := "Unknown"
	if issue.User != nil && issue.User.Login != nil {
		owner = *issue.User.Login
	}

	statusIcon := "CircleHelp"
	statusValue := "Unknown"

	if issue.State != nil {
		switch *issue.State {
		case "open":
			statusIcon = "Circle"
			statusValue = "Open"
		case "closed":
			statusIcon = "CircleCheck"
			statusValue = "Closed"
		}
	}

	return &plugin.Resource{
		Type:        i.Info().ID,
		ID:          fmt.Sprintf("%s/%s/%d", org, repo, number),
		Name:        issue.GetTitle(),
		Icon:        "Github",
		Description: stripmd.Strip(issue.GetBody()),
		URL:         issue.GetHTMLURL(),
		Attributes: []plugin.Attribute{
			{ID: "status", Name: "Status", Icon: statusIcon, Value: statusValue},
			{ID: "repository", Name: "Repository", Icon: "FolderGit2", Value: org + "/" + repo},
			{ID: "owner", Name: "Owner", Icon: "User", Value: owner},
		},
	}, nil
}
