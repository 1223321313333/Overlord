#pragma once
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif
typedef void* overlord_qsv_encoder;
int overlord_qsv_probe(char*, int);
int overlord_qsv_probe_hevc(char*, int);
int overlord_qsv_create(void*, int, int, int, int, int, uint32_t, int,
                        overlord_qsv_encoder*, char*, int);
int overlord_qsv_create_hevc(void*, int, int, int, int, int, uint32_t, int,
                              overlord_qsv_encoder*, char*, int);
int overlord_qsv_encode(overlord_qsv_encoder, void*, int, uint8_t*, int, int*, char*, int);
void overlord_qsv_destroy(overlord_qsv_encoder);
#ifdef __cplusplus
}
#endif
