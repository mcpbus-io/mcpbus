package file

import (
	"encoding/json"
	"errors"
	"strings"
	"text/template"
)

type Backend struct {
	conf         *Config
	pathTemplate *template.Template
}

func New(config json.RawMessage) (*Backend, error) {
	conf := &Config{}
	if err := json.Unmarshal(config, conf); err != nil {
		return nil, err
	}

	if conf.Path == "" {
		return nil, errors.New("path is not set")
	}

	// Parse the URL template
	var pathTemplate *template.Template
	if strings.Contains(conf.Path, "{{") {
		var err error
		pathTemplate, err = template.New("FilePath").Parse(conf.Path)
		if err != nil {
			return nil, err
		}
	}

	return &Backend{
		conf:         conf,
		pathTemplate: pathTemplate,
	}, nil
}
