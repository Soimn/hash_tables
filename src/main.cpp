#include <windows.h>
#include <stdio.h>
#include <unordered_map>
#include <vector>

#define XXH_INLINE_ALL
#include "vendor/xxhash/xxhash.h"

#include "common.h"

#define USAGE_STR "Usage: hash_bench [variant number] [path to c/c++ code or header file]"

#define MAX_STRING_COUNT_LG2 23
#define MAX_STRING_COUNT (1ULL << MAX_STRING_COUNT_LG2)

static void
PreFault(void* base, u64 size)
{
#if 0
  u64 page_size = 1ULL << 14;
  __m256i zero = _mm256_setzero_si256();
  for (u64 i = 0; i < size; i += page_size)
  {
    _mm256_stream_si256((__m256i*)((u8*)base + i), zero);
  }
#endif
}

struct Variant_Data
{
  std::vector<String> strings;

  std::unordered_map<String, u32, String_Hash_XXH64, String_Eq> um;
  std::unordered_map<String, u32, String_Hash_FNV1A, String_Eq> umfnv;

  struct
  {
    struct LP_Entry* entries;
    u64 entry_count;
  } lp;

  struct
  {
    struct OA_Entry* entries;
    u64 entry_count;
  } oa;

  struct
  {
    struct HP_Entry* entries;
    u64 entry_count;
  } hp;

  struct
  {
    struct RP_Entry* entries;
    u64 entry_count;
  } rp;

  Variant_Data() : strings(), um() {}
  ~Variant_Data() = default;
};

typedef struct Variant
{
  void (*init)(Variant_Data* data);
  void (*put)(Variant_Data* data, String s);
  u64 (*size)(Variant_Data* data);
} Variant;

static void
STUB_Init(Variant_Data* data)
{
}

static void
STUB_Put(Variant_Data* data, String s)
{
}

static u64
STUB_Size(Variant_Data* data)
{
  return 0;
}

// ----------------- UM

static void
UM_Init(Variant_Data* data)
{
  data->um.reserve(MAX_STRING_COUNT);
}

static void
UM_Put(Variant_Data* data, String s)
{
  if (data->um.find(s) == data->um.end())
  {
    data->um.emplace(s, (u32)data->strings.size());
    data->strings.push_back(s);
  }
}

static u64
UM_Size(Variant_Data* data)
{
  return data->um.size();
}

// ----------------- LP

typedef struct LP_Entry
{
  u64 hash;
  u32 string_idx;
} LP_Entry;

#define LP_SIZE (1ULL << MAX_STRING_COUNT_LG2)
#define LP_MASK (LP_SIZE-1)

static void
LP_Init(Variant_Data* data)
{
  data->lp.entry_count = 0;
  data->lp.entries = (LP_Entry*)VirtualAlloc(0, LP_SIZE*sizeof(LP_Entry), MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE);
  
  if (data->lp.entries == 0)
  {
    fprintf(stderr, "Failed to allocate memory for Linear Probe hash table\n");
    ExitProcess(-1);
  }

  PreFault(data->lp.entries, LP_SIZE*sizeof(LP_Entry));
}

static void
LP_Put(Variant_Data* data, String s)
{
  u64 hash = XXH3_64bits(s.data, s.len);
  if (hash == 0) hash = 1;

  u64 idx = hash & LP_MASK;

  while (data->lp.entries[idx].hash != 0)
  {
    if (data->lp.entries[idx].hash == hash && data->strings[data->lp.entries[idx].string_idx] == s) break;
    else                                                                                            idx = (idx + 1) & LP_MASK;
  }

  if (data->lp.entries[idx].hash == 0)
  {
    data->lp.entries[idx].hash       = hash;
    data->lp.entries[idx].string_idx = (u32)data->strings.size();
    data->strings.push_back(s);
    data->lp.entry_count += 1;
  }
}

static u64
LP_Size(Variant_Data* data)
{
  return data->lp.entry_count;
}

// ----------------- OA

typedef struct OA_Entry
{
  u64 hash;
  u32 string_idx;
} OA_Entry;

#define OA_BUCKET_SIZE_LG2 14
#define OA_BUCKET_SIZE (1ULL << OA_BUCKET_SIZE_LG2)
#define OA_BUCKET_COUNT (1ULL << (MAX_STRING_COUNT_LG2 - OA_BUCKET_SIZE_LG2))

static void
OA_Init(Variant_Data* data)
{
  data->oa.entry_count = 0;
  data->oa.entries = (OA_Entry*)VirtualAlloc(0, OA_BUCKET_SIZE*OA_BUCKET_COUNT*sizeof(OA_Entry), MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE);
  
  if (data->oa.entries == 0)
  {
    fprintf(stderr, "Failed to allocate memory for Linear Probe hash table\n");
    ExitProcess(-1);
  }
}

static void
OA_Put(Variant_Data* data, String s)
{
  u64 hash = XXH3_64bits(s.data, s.len);
  if (hash == 0) hash = 1;

  u64 bucket_idx = hash & (OA_BUCKET_COUNT-1);

  u64 idx = bucket_idx * OA_BUCKET_SIZE;

  for (; data->oa.entries[idx].hash != 0 && idx < (bucket_idx+1)*OA_BUCKET_SIZE; ++idx)
  {
    if (data->oa.entries[idx].hash == hash && data->strings[data->oa.entries[idx].string_idx] == s) break;
  }

  if (idx == (bucket_idx+1)*OA_BUCKET_SIZE) ExitProcess(-1);

  if (data->oa.entries[idx].hash == 0)
  {
    data->oa.entries[idx].hash       = hash;
    data->oa.entries[idx].string_idx = (u32)data->strings.size();
    data->strings.push_back(s);
    data->oa.entry_count += 1;
  }
}

static u64
OA_Size(Variant_Data* data)
{
  return data->oa.entry_count;
}

// ----------------- HP

typedef struct HP_Entry
{
  u64 hash;
  u32 string_idx;
} HP_Entry;

#define HP_SIZE (1ULL << MAX_STRING_COUNT_LG2)
#define HP_MASK (HP_SIZE-1)

static void
HP_Init(Variant_Data* data)
{
  data->hp.entry_count = 0;
  data->hp.entries = (HP_Entry*)VirtualAlloc(0, HP_SIZE*sizeof(HP_Entry), MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE);
  
  if (data->hp.entries == 0)
  {
    fprintf(stderr, "Failed to allocate memory for Linear Probe hash table\n");
    ExitProcess(-1);
  }

  PreFault(data->hp.entries, HP_SIZE*sizeof(HP_Entry));
}

static void
HP_Put(Variant_Data* data, String s)
{
  u64 hash = XXH3_64bits(s.data, s.len);
  if (hash == 0) hash = 1;

  u64 idx  = hash & HP_MASK;
  u64 step = 1 + ((hash >> 24) & 0x3);

  while (data->hp.entries[idx].hash != 0)
  {
    if (data->hp.entries[idx].hash == hash && data->strings[data->hp.entries[idx].string_idx] == s) break;
    else                                                                                            idx = (idx + step) & HP_MASK;
  }

  if (data->hp.entries[idx].hash == 0)
  {
    data->hp.entries[idx].hash       = hash;
    data->hp.entries[idx].string_idx = (u32)data->strings.size();
    data->strings.push_back(s);
    data->hp.entry_count += 1;
  }
}

static u64
HP_Size(Variant_Data* data)
{
  return data->hp.entry_count;
}

// ----------------- RP

typedef struct RP_Entry
{
  u64 hash;
  u32 string_idx;
} RP_Entry;

#define RP_SIZE_LG2 MAX_STRING_COUNT_LG2
#define RP_SIZE (1ULL << RP_SIZE_LG2)
#define RP_MASK (RP_SIZE-1)

static void
RP_Init(Variant_Data* data)
{
  data->rp.entry_count = 0;
  data->rp.entries = (RP_Entry*)VirtualAlloc(0, RP_SIZE*sizeof(RP_Entry), MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE);
  
  if (data->rp.entries == 0)
  {
    fprintf(stderr, "Failed to allocate memory for Linear Probe hash table\n");
    ExitProcess(-1);
  }

  PreFault(data->rp.entries, RP_SIZE*sizeof(RP_Entry));
}

static void
RP_Put(Variant_Data* data, String s)
{
  u64 hash = XXH3_64bits(s.data, s.len);
  if (hash == 0) hash = 1;

  u64 idx  = hash & RP_MASK;
  u64 step_i = _rotr64(hash, RP_SIZE_LG2);

  while (data->rp.entries[idx].hash != 0)
  {
    if (data->rp.entries[idx].hash == hash && data->strings[data->rp.entries[idx].string_idx] == s) break;
    else                                                                                            idx = (idx + 1 + ((step_i = _rotr64(step_i, 2))&0x3)) & RP_MASK;
  }

  if (data->rp.entries[idx].hash == 0)
  {
    data->rp.entries[idx].hash       = hash;
    data->rp.entries[idx].string_idx = (u32)data->strings.size();
    data->strings.push_back(s);
    data->rp.entry_count += 1;
  }
}

static u64
RP_Size(Variant_Data* data)
{
  return data->rp.entry_count;
}

// ----------------- UMFNV

static void
UMFNV_Init(Variant_Data* data)
{
  data->umfnv.reserve(MAX_STRING_COUNT);
}

static void
UMFNV_Put(Variant_Data* data, String s)
{
  if (data->umfnv.find(s) == data->umfnv.end())
  {
    data->umfnv.emplace(s, (u32)data->strings.size());
    data->strings.push_back(s);
  }
}

static u64
UMFNV_Size(Variant_Data* data)
{
  return data->umfnv.size();
}

// ----------------- LPFNV

#define LPFNV_SIZE_LG2 MAX_STRING_COUNT_LG2
#define LPFNV_SIZE (1ULL << LPFNV_SIZE_LG2)
#define LPFNV_MASK (LPFNV_SIZE-1)

static void
LPFNV_Init(Variant_Data* data)
{
  data->lp.entry_count = 0;
  data->lp.entries = (LP_Entry*)VirtualAlloc(0, LPFNV_SIZE*sizeof(LP_Entry), MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE);
  
  if (data->lp.entries == 0)
  {
    fprintf(stderr, "Failed to allocate memory for Linear Probe hash table\n");
    ExitProcess(-1);
  }

  PreFault(data->lp.entries, LPFNV_SIZE*sizeof(LP_Entry));
}

static void
LPFNV_Put(Variant_Data* data, String s)
{
  u64 hash = FNV1A(s);
  if (hash == 0) hash = 1;

  u64 idx = FNV1A_MapToIdx(hash, LPFNV_SIZE_LG2);

  while (data->lp.entries[idx].hash != 0)
  {
    if (data->lp.entries[idx].hash == hash && data->strings[data->lp.entries[idx].string_idx] == s) break;
    else                                                                                            idx = (idx + 1) & LPFNV_MASK;
  }

  if (data->lp.entries[idx].hash == 0)
  {
    data->lp.entries[idx].hash       = hash;
    data->lp.entries[idx].string_idx = (u32)data->strings.size();
    data->strings.push_back(s);
    data->lp.entry_count += 1;
  }
}

static u64
LPFNV_Size(Variant_Data* data)
{
  return data->lp.entry_count;
}

// ----------------- HPFNV

#define HPFNV_SIZE_LG2 MAX_STRING_COUNT_LG2
#define HPFNV_SIZE (1ULL << HPFNV_SIZE_LG2)
#define HPFNV_MASK (HPFNV_SIZE-1)

static void
HPFNV_Init(Variant_Data* data)
{
  data->hp.entry_count = 0;
  data->hp.entries = (HP_Entry*)VirtualAlloc(0, HPFNV_SIZE*sizeof(HP_Entry), MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE);
  
  if (data->hp.entries == 0)
  {
    fprintf(stderr, "Failed to allocate memory for Linear Probe hash table\n");
    ExitProcess(-1);
  }

  PreFault(data->hp.entries, HPFNV_SIZE*sizeof(HP_Entry));
}

static void
HPFNV_Put(Variant_Data* data, String s)
{
  u64 hash = FNV1A(s);
  if (hash == 0) hash = 1;

  u64 idx = FNV1A_MapToIdx(hash, HPFNV_SIZE_LG2);
  u64 step = 1 + ((hash >> 24) & 0x3);

  while (data->hp.entries[idx].hash != 0)
  {
    if (data->hp.entries[idx].hash == hash && data->strings[data->hp.entries[idx].string_idx] == s) break;
    else                                                                                            idx = (idx + step) & HPFNV_MASK;
  }

  if (data->hp.entries[idx].hash == 0)
  {
    data->hp.entries[idx].hash       = hash;
    data->hp.entries[idx].string_idx = (u32)data->strings.size();
    data->strings.push_back(s);
    data->hp.entry_count += 1;
  }
}

static u64
HPFNV_Size(Variant_Data* data)
{
  return data->hp.entry_count;
}

// ----------------- RPFNV

#define RPFNV_SIZE_LG2 MAX_STRING_COUNT_LG2
#define RPFNV_SIZE (1ULL << RPFNV_SIZE_LG2)
#define RPFNV_MASK (RPFNV_SIZE-1)

static void
RPFNV_Init(Variant_Data* data)
{
  data->rp.entry_count = 0;
  data->rp.entries = (RP_Entry*)VirtualAlloc(0, RPFNV_SIZE*sizeof(RP_Entry), MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE);
  
  if (data->rp.entries == 0)
  {
    fprintf(stderr, "Failed to allocate memory for Linear Probe hash table\n");
    ExitProcess(-1);
  }

  PreFault(data->rp.entries, RPFNV_SIZE*sizeof(RP_Entry));
}

static void
RPFNV_Put(Variant_Data* data, String s)
{
  u64 hash = FNV1A(s);
  if (hash == 0) hash = 1;

  u64 idx = FNV1A_MapToIdx(hash, RPFNV_SIZE_LG2);
  u64 step_i = _rotr64(hash, RPFNV_SIZE_LG2);

  while (data->rp.entries[idx].hash != 0)
  {
    if (data->rp.entries[idx].hash == hash && data->strings[data->rp.entries[idx].string_idx] == s) break;
    else                                                                                            idx = (idx + 1 + ((step_i = _rotr64(step_i, 2))&0x3)) & RPFNV_MASK;
  }

  if (data->rp.entries[idx].hash == 0)
  {
    data->rp.entries[idx].hash       = hash;
    data->rp.entries[idx].string_idx = (u32)data->strings.size();
    data->strings.push_back(s);
    data->rp.entry_count += 1;
  }
}

static u64
RPFNV_Size(Variant_Data* data)
{
  return data->rp.entry_count;
}

Variant Variants[] = {
  { STUB_Init, STUB_Put, STUB_Size },
  { UM_Init, UM_Put, UM_Size },
  { LP_Init, LP_Put, LP_Size },
  { OA_Init, OA_Put, OA_Size },
  { HP_Init, HP_Put, HP_Size },
  { RP_Init, RP_Put, RP_Size },
  { UMFNV_Init, UMFNV_Put, UMFNV_Size },
  { LPFNV_Init, LPFNV_Put, LPFNV_Size },
  { HPFNV_Init, HPFNV_Put, HPFNV_Size },
  { RPFNV_Init, RPFNV_Put, RPFNV_Size },
};

int
main(int argc, char** argv)
{
  if (argc != 3)
  {
    fprintf(stderr, "Invalid Arguments. %s\n", USAGE_STR);
    return -1;
  }

  u64 variant_idx = 0;
  for (char* scan = argv[1]; *scan != 0; ++scan)
  {
    if (!Char_IsDigit(*scan))
    {
      fprintf(stderr, "Invalid Input. Variant number is not a number\n%s\n", USAGE_STR);
      return -1;
    }

    variant_idx = variant_idx*10 + (*scan&0xF);
  }

  if (variant_idx >= ARRAY_SIZE(Variants))
  {
    fprintf(stderr, "Invalid Input. Variant number is too large\n%s\n", USAGE_STR);
    return -1;
  }

  Variant_Data data{};
  Variant variant = Variants[variant_idx];

  data.strings.reserve(MAX_STRING_COUNT);
  variant.init(&data);

  Lexer lexer = Lexer_Init(argv[2]);

  u64 start_rdtsc = __rdtsc();
  u64 watermark = 0;
  printf("%llu, %llu\n", 0ULL, __rdtsc() - start_rdtsc);

  for (;;)
  {
    u64 sz = variant.size(&data);
    if (sz > watermark && sz % 10000 == 0)
    {
      watermark = sz;
      printf("%llu, %llu\n", sz, __rdtsc() - start_rdtsc);
    }

    for (;;)
    {
      Token token = Lexer_NextToken(&lexer);
      if (token.kind == Token_Error || token.kind == Token_EOF || token.kind == Token_Ident) break;
      else                                                                                   continue;
    }

    if (lexer.token.kind == Token_Error || lexer.token.kind == Token_EOF) break;
    else
    {
      variant.put(&data, lexer.token.string);
    }
  }

  if (lexer.token.kind != Token_EOF)
  {
    //// ERROR
    fprintf(stderr, "Lexer error\n");
    return -1;
  }

  printf("Found %llu identifiers\n", variant.size(&data));

  return 0;
}
