#include "Hacl_HMAC_SHA2_256.h"
#include "Hacl_HMAC_SHA2_512.h"

#include <inttypes.h>

void print_buf(uint8_t *buf, size_t size) {
  char *str = malloc(2 * size + 1);
  for (int i = 0; i < size; ++i)
    sprintf(str + 2 * i, "%02x", buf[i]);
  str[2 * size] = '\0';
  printf("%s\n", str);
}

uint8_t key[32] = { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 };
uint8_t tag[64];

int main()
{
  
  Hacl_HMAC_SHA2_512_hmac(tag, key, 32, NULL, 0);

  //print_buf(tag, 32);
  
  return 0;
}
