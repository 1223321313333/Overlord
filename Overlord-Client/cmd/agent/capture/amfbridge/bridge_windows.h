#pragma once
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef void* overlord_amf_encoder;

int overlord_amf_probe(char* error_text, int error_capacity);
int overlord_amf_probe_hevc(char* error_text, int error_capacity);
int overlord_amf_create(void* d3d11_device, int input_width, int input_height,
                        int encode_width, int encode_height, int fps,
                        uint32_t dxgi_format, int bitrate,
                        overlord_amf_encoder* encoder,
                        char* error_text, int error_capacity);
int overlord_amf_create_hevc(void* d3d11_device, int input_width, int input_height,
                              int encode_width, int encode_height, int fps,
                              uint32_t dxgi_format, int bitrate,
                              overlord_amf_encoder* encoder,
                              char* error_text, int error_capacity);
int overlord_amf_encode(overlord_amf_encoder encoder, void* d3d11_texture,
                        int force_idr, uint8_t* output, int output_capacity,
                        int* output_size, char* error_text, int error_capacity);
void overlord_amf_destroy(overlord_amf_encoder encoder);

#ifdef __cplusplus
}
#endif
