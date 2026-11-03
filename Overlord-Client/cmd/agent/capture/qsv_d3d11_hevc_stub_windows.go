//go:build windows && (!cgo || no_qsv)

package capture

func newQSVHEVCD3D11TextureBackend() h264D3D11TextureBackend { return nil }
func probeQSVHEVC() (bool, string)                            { return false, "Intel Quick Sync requires a Windows CGO build" }
