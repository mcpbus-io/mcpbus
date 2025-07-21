package utils

import "github.com/yosida95/uritemplate/v3"

func GetArgumentsFromURI(uriTemplate *uritemplate.Template, uri string) map[string]any {
	arguments := map[string]any{}

	if uriTemplate == nil {
		return arguments
	}

	uriValues := uriTemplate.Match(uri)
	for k, v := range uriValues {
		switch v.T {
		case uritemplate.ValueTypeString:
			arguments[k] = v.String()
		case uritemplate.ValueTypeKV:
			arguments[k] = v.KV()
		case uritemplate.ValueTypeList:
			arguments[k] = v.List()
		}
	}

	return arguments
}
