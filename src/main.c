#define _CRT_SECURE_NO_WARNINGS

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include "types.h"

#define XXH_INLINE_ALL
#include "vendor/xxhash/xxhash.h"

static u64
Hash_XXH64(String key)
{
  return XXH3_64bits(key.data, key.len);
}

#include "repetition_tester.h"

// NOTE: Decisions made about the input to make tests more fair
// - only the pointer to string keys are stored in the tables (this is to avoid problems with pressure on the global heap)
// - keys are not allowed to be a pointer in the zero page (this is to give some of the hash tables a stable sentinel value)
#include "separate_chaining.h"
#include "separate_chaining_w_arrays.h"
#include "separate_chaining_one_array.h"
#include "open_addressing_linear_probing.h"

int
main(int argc, char** argv)
{
  Key_Data_Pair pairs[] = {
    { STRING("hello"),  (void*)0 },
    { STRING("world"),  (void*)1 },
    { STRING("ohayou"), (void*)2 },
    { STRING("sekai"),  (void*)3 },
  };

  printf("done\n");

  return 0;
}
