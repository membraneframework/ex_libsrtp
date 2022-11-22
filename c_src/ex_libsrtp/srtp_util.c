#include "srtp_util.h"
#include <srtp2/srtp.h>
#include <string.h>

bool srtp_util_unmarshal_ssrc(int ssrc_type, unsigned int ssrc,
    srtp_ssrc_t *result) {
  switch (ssrc_type) {
    case ssrc_specific:
      result->type = ssrc_specific;
      result->value = ssrc;
      return true;
    case ssrc_any_inbound:
      result->type = ssrc_any_inbound;
      return true;
    case ssrc_any_outbound:
      result->type = ssrc_any_outbound;
      return true;
    default:
      return false;
  }
}

bool srtp_util_set_crypto_policy_from_crypto_profile_atom(
    char *crypto_profile, srtp_crypto_policy_t *policy) {
  if (strcmp(crypto_profile, "rtp_default") == 0) {
    srtp_crypto_policy_set_rtp_default(policy);
    return true;
  }

  if (strcmp(crypto_profile, "rtcp_default") == 0) {
    srtp_crypto_policy_set_rtcp_default(policy);
    return true;
  }

  if (strcmp(crypto_profile, "aes_cm_128_hmac_sha1_80") == 0) {
    srtp_crypto_policy_set_aes_cm_128_hmac_sha1_80(policy);
    return true;
  }

  if (strcmp(crypto_profile, "aes_cm_128_hmac_sha1_32") == 0) {
    srtp_crypto_policy_set_aes_cm_128_hmac_sha1_32(policy);
    return true;
  }

  if (strcmp(crypto_profile, "aes_cm_128_null_auth") == 0) {
    srtp_crypto_policy_set_aes_cm_128_null_auth(policy);
    return true;
  }

  if (strcmp(crypto_profile, "null_cipher_hmac_sha1_80") == 0) {
    srtp_crypto_policy_set_null_cipher_hmac_sha1_80(policy);
    return true;
  }

  if (strcmp(crypto_profile, "null_cipher_hmac_null") == 0) {
    srtp_crypto_policy_set_null_cipher_hmac_null(policy);
    return true;
  }

  if (strcmp(crypto_profile, "aes_cm_256_hmac_sha1_80") == 0) {
    srtp_crypto_policy_set_aes_cm_256_hmac_sha1_80(policy);
    return true;
  }

  if (strcmp(crypto_profile, "aes_cm_256_hmac_sha1_32") == 0) {
    srtp_crypto_policy_set_aes_cm_256_hmac_sha1_32(policy);
    return true;
  }

  if (strcmp(crypto_profile, "aes_cm_256_null_auth") == 0) {
    srtp_crypto_policy_set_aes_cm_256_null_auth(policy);
    return true;
  }

  if (strcmp(crypto_profile, "aes_cm_192_hmac_sha1_80") == 0) {
    srtp_crypto_policy_set_aes_cm_192_hmac_sha1_80(policy);
    return true;
  }

  if (strcmp(crypto_profile, "aes_cm_192_hmac_sha1_32") == 0) {
    srtp_crypto_policy_set_aes_cm_192_hmac_sha1_32(policy);
    return true;
  }

  if (strcmp(crypto_profile, "aes_cm_192_null_auth") == 0) {
    srtp_crypto_policy_set_aes_cm_192_null_auth(policy);
    return true;
  }

  if (strcmp(crypto_profile, "aes_gcm_128_8_auth") == 0) {
    srtp_crypto_policy_set_aes_gcm_128_8_auth(policy);
    return true;
  }

  if (strcmp(crypto_profile, "aes_gcm_256_8_auth") == 0) {
    srtp_crypto_policy_set_aes_gcm_256_8_auth(policy);
    return true;
  }

  if (strcmp(crypto_profile, "aes_gcm_128_8_only_auth") == 0) {
    srtp_crypto_policy_set_aes_gcm_128_8_only_auth(policy);
    return true;
  }

  if (strcmp(crypto_profile, "aes_gcm_256_8_only_auth") == 0) {
    srtp_crypto_policy_set_aes_gcm_256_8_only_auth(policy);
    return true;
  }

  if (strcmp(crypto_profile, "aes_gcm_128_16_auth") == 0) {
    srtp_crypto_policy_set_aes_gcm_128_16_auth(policy);
    return true;
  }

  if (strcmp(crypto_profile, "aes_gcm_256_16_auth") == 0) {
    srtp_crypto_policy_set_aes_gcm_256_16_auth(policy);
    return true;
  }

  return false;
}

const char *srtp_util_strerror(srtp_err_status_t err) {
  switch (err) {
    case srtp_err_status_ok:
      return "srtp: nothing to report";
    case srtp_err_status_fail:
      return "srtp: unspecified failure";
    case srtp_err_status_bad_param:
      return "srtp: unsupported parameter";
    case srtp_err_status_alloc_fail:
      return "srtp: couldn't allocate memory";
    case srtp_err_status_dealloc_fail:
      return "srtp: couldn't deallocate properly";
    case srtp_err_status_init_fail:
      return "srtp: couldn't initialize";
    case srtp_err_status_terminus:
      return "srtp: can't process as much data as requested";
    case srtp_err_status_auth_fail:
      return "srtp: authentication failure";
    case srtp_err_status_cipher_fail:
      return "srtp: cipher failure";
    case srtp_err_status_replay_fail:
      return "srtp: replay check failed (bad index)";
    case srtp_err_status_replay_old:
      return "srtp: replay check failed (index too old)";
    case srtp_err_status_algo_fail:
      return "srtp: algorithm failed test routine";
    case srtp_err_status_no_such_op:
      return "srtp: unsupported operation";
    case srtp_err_status_no_ctx:
      return "srtp: no appropriate context found";
    case srtp_err_status_cant_check:
      return "srtp: unable to perform desired validation";
    case srtp_err_status_key_expired:
      return "srtp: can't use key any more";
    case srtp_err_status_socket_err:
      return "srtp: error in use of socket";
    case srtp_err_status_signal_err:
      return "srtp: error in use POSIX signals";
    case srtp_err_status_nonce_bad:
      return "srtp: nonce check failed";
    case srtp_err_status_read_fail:
      return "srtp: couldn't read data";
    case srtp_err_status_write_fail:
      return "srtp: couldn't write data";
    case srtp_err_status_parse_err:
      return "srtp: error parsing data";
    case srtp_err_status_encode_err:
      return "srtp: error encoding data";
    case srtp_err_status_semaphore_err:
      return "srtp: error while using semaphores";
    case srtp_err_status_pfkey_err:
      return "srtp: error while using pfkey";
    case srtp_err_status_bad_mki:
      return "srtp: error MKI present in packet is invalid";
    case srtp_err_status_pkt_idx_old:
      return "srtp: packet index is too old to consider";
    case srtp_err_status_pkt_idx_adv:
      return "srtp: packet index advanced, reset needed";
    default:
      return "srtp: unknown error";
  }
}

const char *strp_util_srterror_short(srtp_err_status_t err) {
  switch(err) {
    case 0:
      return "srtp_err_status_ok";
    case 1:
      return "srtp_err_status_fail";
    case 2:
      return "srtp_err_status_bad_param";
    case 3:
      return "srtp_err_status_alloc_fail";
    case 4:
      return "srtp_err_status_dealloc_fail";
    case 5:
      return "srtp_err_status_init_fail";
    case 6:
      return "srtp_err_status_terminus";
    case 7:
      return "srtp_err_status_auth_fail";
    case 8:
      return "srtp_err_status_cipher_fail";
    case 9:
      return "srtp_err_status_replay_fail";
    case 10:
      return "srtp_err_status_replay_old";
    case 11:
      return "srtp_err_status_algo_fail";
    case 12:
      return "srtp_err_status_no_such_op";
    case 13:
      return "srtp_err_status_no_ctx";
    case 14:
      return "srtp_err_status_cant_check";
    case 15:
      return "srtp_err_status_key_expired";
    case 16:
      return "srtp_err_status_socket_err";
    case 17:
      return "srtp_err_status_signal_err";
    case 18:
      return "srtp_err_status_nonce_bad";
    case 19:
      return "srtp_err_status_read_fail";
    case 20:
      return "srtp_err_status_write_fail";
    case 21:
      return "srtp_err_status_parse_err";
    case 22:
      return "srtp_err_status_encode_err";
    case 23:
      return "srtp_err_status_semaphore_err";
    case 24:
      return "srtp_err_status_pfkey_err";
    case 25:
      return "srtp_err_status_bad_mki";
    case 26:
      return "srtp_err_status_pkt_idx_old";
    case 27:
      return "srtp_err_status_pkt_idx_adv";
  }
}
