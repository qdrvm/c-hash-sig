#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

/**
 * Error codes for signature scheme
 */
typedef enum PQSigningError {
  /**
   * Success (not an error)
   */
  Success = 0,
  /**
   * Failed to encode message after maximum number of attempts
   */
  EncodingAttemptsExceeded = 1,
  /**
   * Invalid pointer (null pointer)
   */
  InvalidPointer = 2,
  /**
   * Invalid message length
   */
  InvalidMessageLength = 3,
  /**
   * Unknown error
   */
  UnknownError = 99,
} PQSigningError;

/**
 * Wrapper for signature scheme secret key
 *
 * This is an opaque structure whose fields are not accessible from C code
 */
typedef struct PQSignatureSchemeSecretKey {
  uint8_t _private[0];
} PQSignatureSchemeSecretKey;

/**
 * Wrapper for signature scheme public key
 *
 * This is an opaque structure whose fields are not accessible from C code
 */
typedef struct PQSignatureSchemePublicKey {
  uint8_t _private[0];
} PQSignatureSchemePublicKey;

/**
 * Wrapper for signature
 *
 * This is an opaque structure whose fields are not accessible from C code
 */
typedef struct PQSignature {
  uint8_t _private[0];
} PQSignature;

/**
 * Range representation for C
 */
typedef struct PQRange {
  uint64_t start;
  uint64_t end;
} PQRange;

/**
 * Frees memory allocated for secret key
 * # Safety
 * Pointer must be valid and created via pq_key_gen
 */
void pq_secret_key_free(struct PQSignatureSchemeSecretKey *key);

/**
 * Frees memory allocated for public key
 * # Safety
 * Pointer must be valid and created via pq_key_gen
 */
void pq_public_key_free(struct PQSignatureSchemePublicKey *key);

/**
 * Frees memory allocated for signature
 * # Safety
 * Pointer must be valid and created via pq_sign
 */
void pq_signature_free(struct PQSignature *signature);

/**
 * Frees memory allocated for error description string
 * # Safety
 * Pointer must be valid and created via pq_error_description
 */
void pq_string_free(char *s);

/**
 * Get key activation interval
 * # Safety
 * Pointer must be valid
 */
struct PQRange pq_get_activation_interval(const struct PQSignatureSchemeSecretKey *key);

/**
 * Get prepared interval of the key
 * # Safety
 * Pointer must be valid
 */
struct PQRange pq_get_prepared_interval(const struct PQSignatureSchemeSecretKey *key);

/**
 * Advance key preparation to next interval
 * # Safety
 * Pointer must be valid and mutable
 */
void pq_advance_preparation(struct PQSignatureSchemeSecretKey *key);

/**
 * Get maximum lifetime of signature scheme
 */
uint64_t pq_get_lifetime(void);

/**
 * Generate key pair (public and secret)
 *
 * # Parameters
 * - `activation_epoch`: starting epoch for key activation
 * - `num_active_epochs`: number of active epochs
 * - `pk_out`: pointer to write public key (output)
 * - `sk_out`: pointer to write secret key (output)
 *
 * # Returns
 * Error code (Success = 0 on success)
 *
 * # Safety
 * Pointers pk_out and sk_out must be valid
 */
enum PQSigningError pq_key_gen(uintptr_t activation_epoch,
                               uintptr_t num_active_epochs,
                               struct PQSignatureSchemePublicKey **pk_out,
                               struct PQSignatureSchemeSecretKey **sk_out);

/**
 * Sign a message
 *
 * # Parameters
 * - `sk`: secret key for signing
 * - `epoch`: epoch for which signature is created
 * - `message`: pointer to message
 * - `message_len`: message length (must be MESSAGE_LENGTH = 32)
 * - `signature_out`: pointer to write signature (output)
 *
 * # Returns
 * Error code (Success = 0 on success)
 *
 * # Safety
 * All pointers must be valid
 */
enum PQSigningError pq_sign(const struct PQSignatureSchemeSecretKey *sk,
                            uint32_t epoch,
                            const uint8_t *message,
                            uintptr_t message_len,
                            struct PQSignature **signature_out);

/**
 * Verify a signature
 *
 * # Parameters
 * - `pk`: public key
 * - `epoch`: signature epoch
 * - `message`: pointer to message
 * - `message_len`: message length (must be MESSAGE_LENGTH = 32)
 * - `signature`: signature to verify
 *
 * # Returns
 * 1 if signature is valid, 0 if invalid, negative value on error
 *
 * # Safety
 * All pointers must be valid
 */
int pq_verify(const struct PQSignatureSchemePublicKey *pk,
              uint32_t epoch,
              const uint8_t *message,
              uintptr_t message_len,
              const struct PQSignature *signature);

/**
 * Get error description string
 *
 * # Parameters
 * - `error`: error code
 *
 * # Returns
 * Pointer to C-string with error description.
 * Memory must be freed using pq_string_free
 *
 * # Safety
 * Returned pointer must be freed by caller
 */
char *pq_error_description(enum PQSigningError error);

/**
 * Serialize secret key to bytes
 *
 * # Parameters
 * - `sk`: secret key
 * - `buffer`: buffer for writing
 * - `buffer_len`: buffer size
 * - `written_len`: pointer to write actual data size (output)
 *
 * # Returns
 * Error code
 *
 * # Safety
 * All pointers must be valid
 */
enum PQSigningError pq_secret_key_serialize(const struct PQSignatureSchemeSecretKey *sk,
                                            uint8_t *buffer,
                                            uintptr_t buffer_len,
                                            uintptr_t *written_len);

/**
 * Deserialize secret key from bytes
 *
 * # Parameters
 * - `buffer`: buffer with data
 * - `buffer_len`: buffer size
 * - `sk_out`: pointer to write secret key (output)
 *
 * # Returns
 * Error code
 *
 * # Safety
 * All pointers must be valid
 */
enum PQSigningError pq_secret_key_deserialize(const uint8_t *buffer,
                                              uintptr_t buffer_len,
                                              struct PQSignatureSchemeSecretKey **sk_out);

/**
 * Serialize public key to bytes
 *
 * # Parameters
 * - `pk`: public key
 * - `buffer`: buffer for writing
 * - `buffer_len`: buffer size
 * - `written_len`: pointer to write actual data size (output)
 *
 * # Returns
 * Error code
 *
 * # Safety
 * All pointers must be valid
 */
enum PQSigningError pq_public_key_serialize(const struct PQSignatureSchemePublicKey *pk,
                                            uint8_t *buffer,
                                            uintptr_t buffer_len,
                                            uintptr_t *written_len);

/**
 * Deserialize public key from bytes
 *
 * # Parameters
 * - `buffer`: buffer with data
 * - `buffer_len`: buffer size
 * - `pk_out`: pointer to write public key (output)
 *
 * # Returns
 * Error code
 *
 * # Safety
 * All pointers must be valid
 */
enum PQSigningError pq_public_key_deserialize(const uint8_t *buffer,
                                              uintptr_t buffer_len,
                                              struct PQSignatureSchemePublicKey **pk_out);

/**
 * Serialize signature to bytes
 *
 * # Parameters
 * - `signature`: signature
 * - `buffer`: buffer for writing
 * - `buffer_len`: buffer size
 * - `written_len`: pointer to write actual data size (output)
 *
 * # Returns
 * Error code
 *
 * # Safety
 * All pointers must be valid
 */
enum PQSigningError pq_signature_serialize(const struct PQSignature *signature,
                                           uint8_t *buffer,
                                           uintptr_t buffer_len,
                                           uintptr_t *written_len);

/**
 * Deserialize signature from bytes
 *
 * # Parameters
 * - `buffer`: buffer with data
 * - `buffer_len`: buffer size
 * - `signature_out`: pointer to write signature (output)
 *
 * # Returns
 * Error code
 *
 * # Safety
 * All pointers must be valid
 */
enum PQSigningError pq_signature_deserialize(const uint8_t *buffer,
                                             uintptr_t buffer_len,
                                             struct PQSignature **signature_out);
