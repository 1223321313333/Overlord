//go:build android

package persistence

import "fmt"

func install(_ string) error {
	return fmt.Errorf("persistence is not supported on Android")
}

func configure(_ string) error {
	return fmt.Errorf("persistence is not supported on Android")
}

func getTargetPath() (string, error) {
	return "", fmt.Errorf("persistence is not supported on Android")
}

func uninstall() error {
	return nil
}

func removeCurrentInstall(_ string) error {
	return nil
}
