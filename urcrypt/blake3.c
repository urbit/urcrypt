#include "urcrypt.h"
#include "util.h"
#include <blake3.h>
#include <blake3_impl.h>

typedef blake3_output_t output_t;

void
urcrypt_blake3_hash(size_t message_length,
                    uint8_t *message,
                    uint8_t key[BLAKE3_KEY_LEN],
                    size_t out_length,
                    uint8_t *out)
{
  urcrypt__reverse(message_length, message);
  urcrypt__reverse(BLAKE3_KEY_LEN, key);

  hasher hasher;
  blake3_hasher_init_keyed(&hasher, key);
  blake3_hasher_update(&hasher, message, message_length);
  blake3_hasher_finalize(&hasher, out, out_length);

  urcrypt__reverse(out_length, out);
}

blake3_output_t
urcrypt_blake3_chunk_output(size_t chunk_length;
                            uint8_t *chunk,
                            uint8_t key[BLAKE3_KEY_LEN],
                            uint8_t flags)
{
  urcrypt__reverse(chunk_length, chunk);
  urcrypt__reverse(BLAKE3_KEY_LEN, key);

  blake3_chunk_state cs;
  chunk_state_init(&cs, key, flags);
  chunk_state_update(&cs, chunk, chunk_length);
  return chunk_state_output(&cs);
}

blake3_output_t
urcrypt_blake3_parent_output(blake3_output_t l,
                             blake3_output_t r,
                             uint8_t key[BLAKE3_KEY_LEN],
                             uint8_t flags)
{
  urcrypt__reverse(BLAKE3_KEY_LEN, key);

  uint8_t block[BLAKE3_BLOCK_LEN]
  blake3_compress_in_place(l.cv, l.block, l.block_len, l.counter, l.flags);
  blake3_compress_in_place(r.cv, r.block, r.block_len, r.counter, r.flags);
  store_cv_words(block, l.cv);
  store_cv_words(block+32, r.cv);
  return parent_output(block, key, flags);
}

void
urcrypt_blake3_xof(blake3_output_t o,
                   size_t out_length,
                   uint8_t *out)
{
  output_root_bytes(&o, 0, out, out_length);
  urcrypt__reverse(out_length, out);
}
