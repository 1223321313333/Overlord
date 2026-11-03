//go:build windows && cgo && !no_amf

package capture

import (
	"fmt"
	"overlord-client/cmd/agent/capture/amfbridge"
	"sync"
	"sync/atomic"
	"unsafe"
)

var (
	amfHEVCProbeOnce   sync.Once
	amfHEVCProbeOK     bool
	amfHEVCProbeDetail string
)

func probeAMFHEVC() (bool, string) {
	amfHEVCProbeOnce.Do(func() {
		amfHEVCProbeOK, amfHEVCProbeDetail = amfbridge.ProbeHEVC()
	})
	return amfHEVCProbeOK, amfHEVCProbeDetail
}

type amfHEVCD3D11TextureBackend struct {
	encoder      *amfbridge.Encoder
	device       unsafe.Pointer
	inputWidth   int
	inputHeight  int
	encodeWidth  int
	encodeHeight int
	fps          int
	dxgiFormat   uint32
	output       []byte
	forceIDR     atomic.Bool
}

func newAMFHEVCD3D11TextureBackend() h264D3D11TextureBackend {
	return &amfHEVCD3D11TextureBackend{output: make([]byte, 1024*1024)}
}

func (b *amfHEVCD3D11TextureBackend) Name() string { return "AMD AMF" }

func (b *amfHEVCD3D11TextureBackend) matches(req h264D3D11TextureRequest) bool {
	return b.encoder != nil && b.device == req.Device && b.inputWidth == req.InputWidth &&
		b.inputHeight == req.InputHeight && b.encodeWidth == req.EncodeWidth &&
		b.encodeHeight == req.EncodeHeight && b.fps == req.FPS && b.dxgiFormat == req.DXGIFormat
}

func (b *amfHEVCD3D11TextureBackend) Encode(req h264D3D11TextureRequest) ([]byte, error) {
	if !b.matches(req) {
		b.Reset()
		encoder, err := amfbridge.CreateHEVC(req.Device, req.InputWidth, req.InputHeight, req.EncodeWidth,
			req.EncodeHeight, req.FPS, req.DXGIFormat, targetH264Bitrate(req.EncodeWidth, req.EncodeHeight, req.FPS))
		if err != nil {
			return nil, err
		}
		b.encoder = encoder
		b.device, b.inputWidth, b.inputHeight = req.Device, req.InputWidth, req.InputHeight
		b.encodeWidth, b.encodeHeight, b.fps, b.dxgiFormat = req.EncodeWidth, req.EncodeHeight, req.FPS, req.DXGIFormat
	}
	pendingIDR := b.forceIDR.Swap(false)
	forceIDR := req.ForceIDR || pendingIDR
	for attempts := 0; attempts < 2; attempts++ {
		result, outputSize, err := b.encoder.Encode(req.Texture, forceIDR, b.output)
		if err != nil {
			return nil, err
		}
		if result == 2 {
			if outputSize <= 0 || outputSize > 64*1024*1024 {
				return nil, fmt.Errorf("AMF HEVC returned invalid output size %d", outputSize)
			}
			b.output = make([]byte, outputSize)
			forceIDR = false
			continue
		}
		if outputSize <= 0 {
			return nil, nil
		}
		out := make([]byte, outputSize)
		copy(out, b.output[:outputSize])
		return out, nil
	}
	return nil, fmt.Errorf("AMF HEVC output buffer resize retry failed")
}

func (b *amfHEVCD3D11TextureBackend) RequestKeyframe() { b.forceIDR.Store(true) }

func (b *amfHEVCD3D11TextureBackend) Reset() {
	if b.encoder != nil {
		b.encoder.Close()
	}
	b.encoder = nil
	b.device = nil
	b.forceIDR.Store(false)
}
