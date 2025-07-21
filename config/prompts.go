package config

import (
	"encoding/json"
	"fmt"
	"strings"
	"text/template"

	mcptypes "github.com/mark3labs/mcp-go/mcp"
)

type PromptMessage struct {
	Role         string
	ContentType  string
	Content      mcptypes.Content
	TextTemplate *template.Template
	URITemplate  *template.Template
}

type MessageResource struct {
	mcptypes.Annotated
	Type        string          `json:"type"`
	ResourceRaw json.RawMessage `json:"resource"`
}

func (m *PromptMessage) UnmarshalJSON(b []byte) error {
	rawPromptMessage := struct {
		Role        string          `json:"role"`
		ContentType string          `json:"contentType"`
		ContentRaw  json.RawMessage `json:"content"`
	}{}

	if err := json.Unmarshal(b, &rawPromptMessage); err != nil {
		return err
	}

	m.Role = rawPromptMessage.Role
	m.ContentType = rawPromptMessage.ContentType

	var textTemplate *template.Template
	var uriTemplate *template.Template

	// set content depending on content type
	contentType := strings.ToLower(m.ContentType)
	switch contentType {
	case "text":
		textContent := &mcptypes.TextContent{}
		if err := json.Unmarshal(rawPromptMessage.ContentRaw, textContent); err != nil {
			return err
		}
		textContent.Type = contentType
		if strings.Contains(textContent.Text, "{{") {
			var err error
			textTemplate, err = template.New("text").Parse(textContent.Text)
			if err != nil {
				return err
			}
		}
		m.Content = textContent
	case "image":
		// TODO: add populating Data from file
		imageContent := &mcptypes.ImageContent{}
		if err := json.Unmarshal(rawPromptMessage.ContentRaw, imageContent); err != nil {
			return err
		}
		imageContent.Type = contentType
		m.Content = imageContent
	case "audio":
		// TODO: add populating Data from file
		audioContent := &mcptypes.AudioContent{}
		if err := json.Unmarshal(rawPromptMessage.ContentRaw, audioContent); err != nil {
			return err
		}
		audioContent.Type = contentType
		m.Content = audioContent
	case "resource":
		resource := &MessageResource{}
		if err := json.Unmarshal(rawPromptMessage.ContentRaw, resource); err != nil {
			return err
		}
		resourceContent := &mcptypes.EmbeddedResource{
			Annotated: resource.Annotated,
			Type:      contentType,
		}
		// set resource content depending on type
		switch strings.ToLower(resource.Type) {
		case "text":
			// TODO: add populating Text from file
			textResContent := &mcptypes.TextResourceContents{}
			if err := json.Unmarshal(resource.ResourceRaw, textResContent); err != nil {
				return err
			}
			if strings.Contains(textResContent.Text, "{{") {
				var err error
				textTemplate, err = template.New("text").Parse(textResContent.Text)
				if err != nil {
					return err
				}
			}
			if strings.Contains(textResContent.URI, "{{") {
				var err error
				uriTemplate, err = template.New("uri").Parse(textResContent.URI)
				if err != nil {
					return err
				}
			}
			resourceContent.Resource = textResContent
		case "blob":
			// TODO: add populating Blob from file
			blobResContent := &mcptypes.BlobResourceContents{}
			if err := json.Unmarshal(resource.ResourceRaw, blobResContent); err != nil {
				return err
			}
			if strings.Contains(blobResContent.URI, "{{") {
				var err error
				uriTemplate, err = template.New("uri").Parse(blobResContent.URI)
				if err != nil {
					return err
				}
			}
			resourceContent.Resource = blobResContent
		default:
			return fmt.Errorf("unknown resource type: %s", resource.Type)
		}
		m.Content = resourceContent
	default:
		return fmt.Errorf("unknown content type: %s", m.ContentType)
	}
	m.TextTemplate = textTemplate
	m.URITemplate = uriTemplate

	return nil
}

type PromptResultTemplate struct {
	Description string          `json:"description,omitempty"`
	Messages    []PromptMessage `json:"messages"`
}

type Prompt struct {
	mcptypes.Prompt
	ResultTemplate PromptResultTemplate `json:"resultTemplate"`
}
