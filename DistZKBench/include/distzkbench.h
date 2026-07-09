#ifndef DISTZKBENCH_H
#define DISTZKBENCH_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct Dzb Dzb;

typedef struct DzbBuffer {
  unsigned char *ptr;
  size_t len;
} DzbBuffer;

Dzb *dzb_init(void);
void dzb_free(Dzb *handle);
uint32_t dzb_rank(Dzb *handle);
uint32_t dzb_world_size(Dzb *handle);
uint32_t dzb_master_rank(Dzb *handle);
int dzb_send(Dzb *handle, uint32_t dst, uint32_t tag, const unsigned char *ptr, size_t len);
DzbBuffer dzb_recv(Dzb *handle, uint32_t src, uint32_t tag);
void dzb_buf_free(DzbBuffer buffer);
int dzb_phase_start(Dzb *handle, const char *name);
int dzb_phase_end(Dzb *handle);
int dzb_metric_u64(Dzb *handle, const char *name, uint64_t value);
int dzb_artifact_write(Dzb *handle, const char *name, const unsigned char *ptr, size_t len);
int dzb_publish_proof_bytes(Dzb *handle, const unsigned char *ptr, size_t len);
int dzb_finish(Dzb *handle);
const char *dzb_last_error(void);

#ifdef __cplusplus
}
#endif

#endif
