typedef struct SC_Table_Entry
{
  struct SC_Table_Entry* next;
  u64 hash;
  String key;
  void* data;
} SC_Table_Entry;

typedef struct SC_Table
{
  Hash_Func* hash_func;
  SC_Table_Entry** buckets;
  u32 bucket_count;
} SC_Table;

static bool
SC_Table_Create(Hash_Func* hash_func, u32 bucket_count, SC_Table* table)
{
  SC_Table_Entry** buckets = calloc(bucket_count, sizeof(SC_Table_Entry*));

  if (buckets == 0) return false;
  else
  {
    *table = (SC_Table){
      .hash_func    = hash_func,
      .buckets      = buckets,
      .bucket_count = bucket_count,
    };

    return true;
  }
}

static void
SC_Table_Destroy(SC_Table* table)
{
  for (u32 i = 0; i < table->bucket_count; ++i)
  {
    SC_Table_Entry* scan = table->buckets[i];
    while (scan != 0)
    {
      SC_Table_Entry* next = scan->next;

      free(scan);

      scan = next;
    }
  }

  free(table->buckets);
  *table = (SC_Table){0};
}

static SC_Table_Entry**
SC_Table__FindEntry(SC_Table* table, u64 hash, String key)
{
  u64 bucket_idx = hash % table->bucket_count;

  SC_Table_Entry** entry = &table->buckets[bucket_idx];

  while (*entry != 0)
  {
    if ((*entry)->hash == hash && String_Match((*entry)->key, key))
    {
      break;
    }
    else entry = &(*entry)->next;
  }

  return entry;
}

static bool
SC_Table_Put(SC_Table* table, String key, void* data)
{
  u64 hash = table->hash_func(key);
  SC_Table_Entry** entry = SC_Table__FindEntry(table, hash, key);

  if (*entry != 0)
  {
    (*entry)->data = data;
  }
  else
  {
    *entry = malloc(sizeof(SC_Table_Entry));
    if (*entry == 0) return false;

    **entry = (SC_Table_Entry){
      .next = 0,
      .hash = hash,
      .key  = key,
      .data = data,
    };
  }

  return true;
}

static bool
SC_Table_Get(SC_Table* table, String key, void** data)
{
  u64 hash = table->hash_func(key);
  SC_Table_Entry* entry = *SC_Table__FindEntry(table, hash, key);

  if (entry == 0) return false;
  else
  {
    *data = entry->data;
    return true;
  }
}

static bool
SC_Table_Remove(SC_Table* table, String key)
{
  u64 hash = table->hash_func(key);
  SC_Table_Entry** entry = SC_Table__FindEntry(table, hash, key);

  if (*entry == 0) return false;
  else
  {
    *entry = (*entry)->next;
    free(*entry);
  }
}
