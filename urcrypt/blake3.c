#include "urcrypt.h"
#include "util.h"
#include <blake3.h>
#include <blake3_impl.h>

void
urcrypt_blake3_hash(size_t message_length,
                    uint8_t *message,
                    uint8_t key[BLAKE3_KEY_LEN],
                    uint8_t flags,
                    size_t out_length,
                    uint8_t *out)
{
  blake3_hasher hasher;
  blake3_hasher_init_raw(&hasher, key, flags);
  blake3_hasher_update(&hasher, message, message_length);
  blake3_hasher_finalize(&hasher, out, out_length);
}

void
urcrypt_blake3_chunk_output(size_t chunk_length,
                            uint8_t *chunk,
                            uint8_t cv[BLAKE3_OUT_LEN],
                            uint8_t block[BLAKE3_BLOCK_LEN],
                            uint8_t *block_len,
                            uint64_t *counter,
                            uint8_t *flags)
{
  uint32_t cv_words[8];
  load_key_words(cv, cv_words);
  uint8_t block_flags = *flags | CHUNK_START;
  while (chunk_length > BLAKE3_BLOCK_LEN) {
    blake3_compress_in_place(cv_words, chunk, BLAKE3_BLOCK_LEN, *counter, block_flags);
    chunk = &chunk[BLAKE3_BLOCK_LEN];
    chunk_length -= BLAKE3_BLOCK_LEN;
    block_flags = *flags;
  }
  store_cv_words(cv, cv_words);
  memset(block, 0, BLAKE3_BLOCK_LEN);
  memcpy(block, chunk, chunk_length);
  *block_len = chunk_length;
  *flags = block_flags | CHUNK_END;
}

void
urcrypt_blake3_compress(uint8_t cv[BLAKE3_OUT_LEN],
                        uint8_t block[BLAKE3_BLOCK_LEN],
                        uint8_t block_len,
                        uint64_t counter,
                        uint8_t flags,
                        uint8_t out[BLAKE3_BLOCK_LEN])
{
  uint32_t cv_words[8];
  load_key_words(cv, cv_words);
  blake3_compress_xof(cv_words, block, block_len, counter, flags, out);
}
