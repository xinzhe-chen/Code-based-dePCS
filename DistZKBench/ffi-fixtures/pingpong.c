#include "distzkbench.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

int main(void) {
  Dzb *dzb = dzb_init();
  if (!dzb) {
    fprintf(stderr, "dzb_init failed: %s\n", dzb_last_error());
    return 1;
  }

  const unsigned char payload[] = "ffi-ping";
  uint32_t rank = dzb_rank(dzb);
  uint32_t world_size = dzb_world_size(dzb);
  if (dzb_phase_start(dzb, "ffi.pingpong") != 0) {
    fprintf(stderr, "phase start failed: %s\n", dzb_last_error());
    dzb_free(dzb);
    return 1;
  }

  if (world_size >= 2 && rank == 0) {
    if (dzb_send(dzb, 1, 99, payload, strlen((const char *)payload)) != 0) {
      fprintf(stderr, "send failed: %s\n", dzb_last_error());
      dzb_free(dzb);
      return 1;
    }
    DzbBuffer reply = dzb_recv(dzb, 1, 100);
    if (!reply.ptr) {
      fprintf(stderr, "recv failed: %s\n", dzb_last_error());
      dzb_free(dzb);
      return 1;
    }
    dzb_buf_free(reply);
  } else if (world_size >= 2 && rank == 1) {
    DzbBuffer got = dzb_recv(dzb, 0, 99);
    if (!got.ptr) {
      fprintf(stderr, "recv failed: %s\n", dzb_last_error());
      dzb_free(dzb);
      return 1;
    }
    dzb_buf_free(got);
    const unsigned char reply[] = "ffi-pong";
    if (dzb_send(dzb, 0, 100, reply, strlen((const char *)reply)) != 0) {
      fprintf(stderr, "send failed: %s\n", dzb_last_error());
      dzb_free(dzb);
      return 1;
    }
  }

  dzb_metric_u64(dzb, "ffi_fixture_reached", 1);
  dzb_phase_end(dzb);
  if (dzb_finish(dzb) != 0) {
    fprintf(stderr, "finish failed: %s\n", dzb_last_error());
    return 1;
  }
  return 0;
}
