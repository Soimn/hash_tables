typedef struct OALP_Table_Entry
{
  u64 hash;
  String key;
  void* data;
} OALP_Table_Entry;

typedef struct OALP_Table
{
  Hash_Func* hash_func;
  OALP_Table_Entry* entries;
  u64 size;
  u64 entry_count;
  u8 load_factor_percent;
} OALP_Table;

#define OALP_TABLE_EMPTY_SLOT 0
#define OALP_TABLE_TOMBSTONE 1
#define OALP_TABLE_LARGEST_SENTINEL_VALUE 1

static u64 OALP_Table__Probe(OALP_Table* table, u64 hash, String key, s64* last_tombstone);

static bool
OALP_Table_Create(Hash_Func* hash_func, u64 initial_size, OALP_Table* table)
{
  OALP_Table_Entry* entries = calloc(initial_size, sizeof(OALP_Table_Entry));

  if (entries == 0) return false;
  else
  {
    *table = (OALP_Table){
      .hash_func    = hash_func,
      .entries      = entries,
      .size         = initial_size,
    };

    return true;
  }
}

static void
OALP_Table_Destroy(OALP_Table* table)
{
  free(table->entries);
  *table = (OALP_Table){0};
}

static u64
OALP_Table__HashKey(OALP_Table* table, String key)
{
  u64 hash = table->hash_func(key);
  if (hash < OALP_TABLE_LARGEST_SENTINEL_VALUE + 1) hash = OALP_TABLE_LARGEST_SENTINEL_VALUE + 1;
  return hash;
}

static u64
OALP_Table__Probe(OALP_Table* table, u64 hash, String key, s64* last_tombstone)
{
  for (u64 idx = hash % table->size;; idx = (idx + 1) % table->size)
  {
    if ((u64)table->entries[idx].hash == OALP_TABLE_TOMBSTONE) *last_tombstone = idx;
    else
    {
      if ((u64)table->entries[idx].hash == OALP_TABLE_EMPTY_SLOT || table->entries[idx].hash == hash && String_Match(table->entries[idx].key, key))
      {
        return idx;
      }
    }
  }
}

static bool
OALP_Table_Put(OALP_Table* table, String key, void* data)
{
  u64 hash = OALP_Table__HashKey(table, key);
  s64 last_tombstone = -1;
  u64 idx = OALP_Table__Probe(table, hash, key, &last_tombstone);

  if ((u64)table->entries[idx].hash > OALP_TABLE_LARGEST_SENTINEL_VALUE) table->entries[idx].data = data;
  else
  {
    if (last_tombstone != -1) idx = last_tombstone;

    table->entries[idx] = (OALP_Table_Entry){
      .hash = hash,
      .key  = key,
      .data = data,
    };

    table->entry_count += 1;
  }

  // table->entry_count/table->size > load_factor_percent/100
  if (table->entry_count*100 > table->load_factor_percent*table->size)
  {
    // TODO: resize
    return false;
  }
  
  return true;
}

static bool
OALP_Table_Get(OALP_Table* table, String key, void** data)
{
  u64 hash = OALP_Table__HashKey(table, key);
  u64 idx = OALP_Table__Probe(table, hash, key, &(s64){0});

  if ((u64)table->entries[idx].hash <= OALP_TABLE_LARGEST_SENTINEL_VALUE) return false;
  else
  {
    *data = table->entries[idx].data;
    return true;
  }
}

static bool
OALP_Table_Remove(OALP_Table* table, String key)
{
  u64 hash = OALP_Table__HashKey(table, key);
  u64 idx = OALP_Table__Probe(table, hash, key, &(s64){0});

  if ((u64)table->entries[idx].hash != OALP_TABLE_EMPTY_SLOT) table->entries[idx].hash = OALP_TABLE_TOMBSTONE;
}
