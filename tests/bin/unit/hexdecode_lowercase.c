#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "../../utils.h"
#include "../../acvp.h"

int main(void) {
  initTest();

  const char* hex = "0a1b2c3d4e5f";
  uint8_t out[6] = {0};

  int err = hexDecode(hex, out, sizeof(out));
  if (err) {
    eprintf("hexDecode returned error: %d\n", err);
    return 1;
  }

  uint8_t expected[] = {0x0a, 0x1b, 0x2c, 0x3d, 0x4e, 0x5f};
  if (memcmp(out, expected, sizeof(expected)) != 0) {
    eprintf("decoded bytes mismatch\n");
    return 2;
  }

  printf("lowercase hex decoded ok\n");
  return 0;
}
