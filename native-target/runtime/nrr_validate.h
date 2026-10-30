#pragma once
#include <stddef.h>
#include <stdint.h>

/* Diagnostic host resource cap; not a Horizon maximum or title contract. */
#define RUNTIME_NRR_MAX_BYTES (1024u*1024u)
typedef struct {
    uint32_t hashes_offset,hash_count,key_generation;
    uint8_t signed_area_sha256[32];
} RuntimeNrrValidated;

/* Validate an immutable snapshot with pinned public production roots only.
 * Returns NULL on success or a specific rejection diagnostic. Neither this
 * function nor its caller maps/executes an NRO or treats an AOT hash as trusted. */
const char *runtime_nrr_validate(const uint8_t *snapshot,size_t size,
                                 uint64_t program_id,RuntimeNrrValidated *out);
