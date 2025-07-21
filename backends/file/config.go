package file

type Config struct {
	Path              string `json:"path"`
	EnableWalkthrough bool   `json:"enableWalkThrough"`
	FileHeadInDesc    bool   `json:"fileHeadInDesc"`
}
