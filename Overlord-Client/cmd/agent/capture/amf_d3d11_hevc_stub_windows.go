//go:build windows && (!cgo || no_amf)

package capture

func newAMFHEVCD3D11TextureBackend() h264D3D11TextureBackend { return nil }
func probeAMFHEVC() (bool, string)                            { return false, "AMD AMF requires a Windows CGO build" }
