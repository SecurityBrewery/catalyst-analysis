package main

import (
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/forensicanalysis/gitfs"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

const iconTemplate = `// Code generated by scripts/lucide.go. DO NOT EDIT.
package icons

var Icons = []string{
{{range . -}}
	"{{.}}",
{{end}}
}`

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	fsys, err := gitfs.New("https://github.com/lucide-icons/lucide")
	if err != nil {
		return err
	}

	entries, err := fs.ReadDir(fsys, "icons")
	if err != nil {
		return err
	}

	var icons []string

	for _, entry := range entries {
		ext := filepath.Ext(entry.Name())
		if entry.IsDir() || ext != ".json" {
			continue
		}

		filename := strings.TrimSuffix(entry.Name(), ext)

		icons = append(icons, kebabToCamel(filename))
	}

	tmpl := template.New("iconTemplate")

	tmpl, err = tmpl.Parse(iconTemplate)
	if err != nil {
		return err
	}

	_ = os.MkdirAll("icons", 0o755)

	f, err := os.Create("icons/icons.go")
	if err != nil {
		return err
	}
	defer f.Close()

	return tmpl.Execute(f, icons)
}

func kebabToCamel(filename string) string {
	parts := strings.Split(filename, "-")
	for i, part := range parts {
		parts[i] = cases.Title(language.Und, cases.NoLower).String(part)
	}

	return strings.Join(parts, "")
}
