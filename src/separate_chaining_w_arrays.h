typedef struct SCWA_Table_Entry
{
  u64 hash;
  String key;
  u64 data;
} SCWA_Table_Entry;

typedef struct SCWA_Bucket
{
  u32 size;
  u32 cap;
  SCWA_Table_Entry entries[];
} SCWA_Bucket;

typedef struct SCWA_Table
{
  Hash_Func* hash_func;
  SCWA_Bucket** buckets;
  u32 bucket_count;
} SCWA_Table;

static bool
SCWA_Table_Create(Hash_Func* hash_func, u32 bucket_count, SCWA_Table* table)
{
  SCWA_Bucket** buckets = calloc(bucket_count, sizeof(SCWA_Bucket*));

  if (buckets == 0) return false;
  else
  {
    *table = (SCWA_Table){
      .hash_func    = hash_func,
      .buckets      = buckets,
      .bucket_count = bucket_count,
    };

    return true;
  }
}

static void
SCWA_Table_Destroy(SCWA_Table* table)
{
  for (u32 i = 0; i < table->bucket_count; ++i)
  {
    free(table->buckets[i]);
  }

  free(table->buckets);
  *table = (SCWA_Table){0};
}

static s64
SCWA_Table__FindEntry(SCWA_Table* table, u64 hash, u64 bucket_idx, String key)
{
  SCWA_Bucket* bucket = table->buckets[bucket_idx];

  if (bucket != 0)
  {
    for (u32 i = 0; i < bucket->size; ++i)
    {
      if (bucket->entries[i].hash == hash && String_Match(bucket->entries[i].key, key))
      {
        return (s64)i;
      }
    }
  }

  return -1;
}

static bool
SCWA_Table_Put(SCWA_Table* table, String key, u64 data)
{
  u64 hash = table->hash_func(key);
  u64 bucket_idx = hash % table->bucket_count;

  s64 idx = SCWA_Table__FindEntry(table, hash, bucket_idx, key);

  if (idx != -1)
  {
    table->buckets[bucket_idx]->entries[idx].data = data;
  }
  else
  {
    SCWA_Bucket** bucket = &table->buckets[bucket_idx];

    if (*bucket == 0 || (*bucket)->size == (*bucket)->cap)
    {
      u32 new_size = (*bucket == 0 ? 0  : (*bucket)->size);
      u32 new_cap  = (*bucket == 0 ? 32 : 2*(*bucket)->cap);

      SCWA_Bucket* new_bucket = realloc(*bucket, sizeof(SCWA_Bucket) + new_cap*sizeof(SCWA_Table_Entry));
      if (new_bucket == 0) return false;

      *bucket = new_bucket;
      (*bucket)->size = new_size;
      (*bucket)->cap  = new_cap;
    }

    (*bucket)->entries[(*bucket)->size++] = (SCWA_Table_Entry){
      .hash = hash,
      .key  = key,
      .data = data,
    };
  }

  return true;
}

static bool
SCWA_Table_Get(SCWA_Table* table, String key, u64* data)
{
  u64 hash = table->hash_func(key);
  u64 bucket_idx = hash % table->bucket_count;

  s64 idx = SCWA_Table__FindEntry(table, hash, bucket_idx, key);

  if (idx == -1) return false;
  else
  {
    *data = table->buckets[bucket_idx]->entries[idx].data;
    return true;
  }
}
