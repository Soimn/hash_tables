typedef struct SCOA_Table_Entry
{
  u64 hash;
  String key;
  void* data;
} SCOA_Table_Entry;

typedef struct SCOA_Table
{
  Hash_Func* hash_func;
  SCOA_Table_Entry* buckets;
  u32 bucket_size;
  u32 bucket_count;
} SCOA_Table;

static bool
SCOA_Table_Create(Hash_Func* hash_func, u32 bucket_size, u32 bucket_count, SCOA_Table* table)
{
  SCOA_Table_Entry* buckets = calloc((u64)bucket_size*(u64)bucket_count, sizeof(SCOA_Table_Entry));

  if (buckets == 0) return false;
  else
  {
    *table = (SCOA_Table){
      .hash_func    = hash_func,
      .buckets      = buckets,
      .bucket_size  = bucket_size,
      .bucket_count = bucket_count,
    };

    return true;
  }
}

static void
SCOA_Table_Destroy(SCOA_Table* table)
{
  free(table->buckets);
  *table = (SCOA_Table){0};
}

static u64
SCOA_Table__HashKey(SCOA_Table* table, String key)
{
  u64 hash = table->hash_func(key);
  if (hash == 0) hash = 1;
  return hash;
}

static s64
SCOA_Table__FindEntry(SCOA_Table* table, u64 hash, String key)
{
  u64 bucket_idx = hash % table->bucket_count;

  SCOA_Table_Entry* bucket = &table->buckets[bucket_idx * table->bucket_size];

  for (s64 idx = 0; idx < table->bucket_size; ++idx)
  {
    if (bucket[idx].hash == 0 || bucket[idx].hash == hash && String_Match(bucket[idx].key, key))
    {
      return (bucket_idx * table->bucket_size) + idx;
    }
  }

  return -1;
}

static bool
SCOA_Table_Put(SCOA_Table* table, String key, void* data)
{
  u64 hash = SCOA_Table__HashKey(table, key);
  s64 idx = SCOA_Table__FindEntry(table, hash, key);

  if (idx == -1)
  {
    // TODO: resize and insert new element
    return false;
  }
  else
  {
    table->buckets[idx].hash = hash;
    table->buckets[idx].key  = key;
  }

  table->buckets[idx].data = data;

  return true;
}

static bool
SCOA_Table_Get(SCOA_Table* table, String key, void** data)
{
  u64 hash = SCOA_Table__HashKey(table, key);
  s64 idx = SCOA_Table__FindEntry(table, hash, key);

  if (idx == -1 || table->buckets[idx].hash == 0) return false;
  else
  {
    *data = table->buckets[idx].data;

    return true;
  }
}

static bool
SCOA_Table_Remove(SCOA_Table* table, String key)
{
  u64 hash = SCOA_Table__HashKey(table, key);
  u64 bucket_idx = hash % table->bucket_count;

  SCOA_Table_Entry* bucket = &table->buckets[bucket_idx * table->bucket_size];

  u64 idx = 0;
  for (; idx < table->bucket_size; ++idx)
  {
    if (bucket[idx].hash == 0 || bucket[idx].hash == hash && String_Match(bucket[idx].key, key))
    {
      break;
    }
  }

  if (idx >= table->bucket_size || bucket[idx].hash == 0) return false;
  else
  {
    u64 last_idx = idx;
    while (last_idx < table->bucket_size-1 && bucket[last_idx].hash != 0) ++last_idx;

    bucket[idx] = bucket[last_idx];
    if (last_idx != idx) bucket[last_idx].hash = 0;

    return true;
  }
}
