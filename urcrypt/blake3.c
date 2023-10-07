#include "urcrypt.h"
#include "util.h"
#include <blake3.h>
#include <blake3_impl.h>

void
urcrypt_blake3_hash(size_t message_length,
                    uint8_t *message,
                    uint8_t key[BLAKE3_KEY_LEN],
                    size_t out_length,
                    uint8_t *out)
{
  // NOTE: inputs are not reversed

  blake3_hasher hasher;
  if (memcmp(key, IV, 32) == 0) {
    blake3_hasher_init(&hasher);
  } else {
    blake3_hasher_init_keyed(&hasher, key);
  }
  blake3_hasher_update(&hasher, message, message_length);
  blake3_hasher_finalize(&hasher, out, out_length);

  urcrypt__reverse(out_length, out);
}

static blake3_output_t cast_output(output_t o) {
  blake3_output_t out;
  memcpy(out.input_cv, o.input_cv, 8 * sizeof(uint32_t));
  memcpy(out.block, o.block, BLAKE3_BLOCK_LEN);
  out.block_len = o.block_len;
  out.counter = o.counter;
  out.flags = o.flags;
  return out;
}

blake3_output_t
urcrypt_blake3_subtree_output(size_t subtree_height,
                            uint8_t *subtree_leaves,
                            uint64_t counter,
                            uint8_t key[BLAKE3_KEY_LEN],
                            uint8_t flags)
{
  size_t subtree_length = ((size_t)1 << subtree_height) * BLAKE3_CHUNK_LEN;
  urcrypt__reverse(subtree_length, subtree_leaves);
  urcrypt__reverse(BLAKE3_KEY_LEN, key);

  uint8_t block[BLAKE3_BLOCK_LEN];
  blake3i_compress_subtree_to_parent_node(subtree_leaves, subtree_length, (uint32_t*)key, counter, flags, block);
  return cast_output(blake3i_parent_output(block, (uint32_t*)key, flags));
}

blake3_output_t
urcrypt_blake3_parent_output(blake3_output_t l,
                             blake3_output_t r,
                             uint8_t key[BLAKE3_KEY_LEN],
                             uint8_t flags)
{
  urcrypt__reverse(BLAKE3_KEY_LEN, key);

  uint8_t block[BLAKE3_BLOCK_LEN];
  blake3_compress_in_place(l.input_cv, l.block, l.block_len, l.counter, l.flags);
  blake3_compress_in_place(r.input_cv, r.block, r.block_len, r.counter, r.flags);
  store_cv_words(block, l.input_cv);
  store_cv_words(block+32, r.input_cv);
  return cast_output(blake3i_parent_output(block, (uint32_t*)key, flags));
}

void
urcrypt_blake3_xof(blake3_output_t o,
                   size_t out_length,
                   uint8_t *out)
{
  output_t o_cast;
  memcpy(o_cast.input_cv, o.input_cv, 8 * sizeof(uint32_t));
  memcpy(o_cast.block, o.block, BLAKE3_BLOCK_LEN);
  o_cast.block_len = o.block_len;
  o_cast.counter = o.counter;
  o_cast.flags = o.flags;
  blake3i_output_root_bytes(&o_cast, 0, out, out_length);
  urcrypt__reverse(out_length, out);
}
