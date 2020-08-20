#include "srtp.h"
#include "srtp_util.h"
#include "unifex_util.h"

#include <stdbool.h>

#ifdef _WIN32
#include <winsock.h>
#else
#include <arpa/inet.h>
#endif

#define EXCEPTION_MESSAGE_SIZE 512

int on_load(UnifexEnv *env, void **priv_data) {
  UNIFEX_UNUSED(env);
  UNIFEX_UNUSED(priv_data);

  srtp_init();

  return 0;
}

void on_unload(UnifexEnv *env, void *priv_data) {
  UNIFEX_UNUSED(env);
  UNIFEX_UNUSED(priv_data);

  srtp_shutdown();
}

void handle_destroy_state(UnifexEnv *env, UnifexState *state) {
  if (state->session) {
    srtp_dealloc(state->session);
    state->session = NULL;
  }

  unifex_release_state(env, state);
}

static void free_master_keys_array(srtp_policy_t *policy) {
  if (!policy->keys && policy->num_master_keys > 0) {
    for (size_t i = 0; i < policy->num_master_keys; i++) {
      srtp_master_key_t *key = policy->keys[i];
      unifex_free(key);
    }

    unifex_free(policy->keys);
    policy->keys = NULL;
    policy->num_master_keys = 0;
  }
}

static bool create_master_keys_array(UnifexEnv *env, UnifexPayload **keys,
                                     unsigned int keys_length,
                                     UnifexPayload **keys_mkis,
                                     unsigned int keys_mkis_length,
                                     srtp_policy_t *policy, UNIFEX_TERM *err) {
  if (keys_length == 0) {
    *err = unifex_raise_args_error(env, "keys", "must not be empty");
    return false;
  }

  // Validate key length
  for (size_t i = 0; i < keys_length; i++) {
    unsigned int expected_length = policy->rtp.cipher_key_len;
    if (keys[i]->size != expected_length) {
      char message[EXCEPTION_MESSAGE_SIZE];
      snprintf(message, EXCEPTION_MESSAGE_SIZE,
               "srtp: master key #%zu must have length of %d but has %d", i,
               expected_length, keys[i]->size);
      *err = unifex_raise(env, message);
      return false;
    }
  }

  // Single master key scenario
  if (keys_length == 1 && keys_mkis_length == 0) {
    policy->key = keys[0]->data;
    return true;
  }

  if (keys_length != keys_mkis_length) {
    *err = unifex_raise_args_error(env, "keys_mkis",
                                   "must be of same length as keys");
    return false;
  }

  policy->keys = unifex_alloc(sizeof(srtp_master_key_t *) * keys_length);
  policy->num_master_keys = keys_length;
  if (!policy->keys) {
    free_master_keys_array(policy);
    *err = unifex_raise(env, "not enough memory");
    return false;
  }

  // Set all pointers to NULL
  memset(policy->keys, 0, sizeof(srtp_master_key_t *) * keys_length);

  for (size_t i = 0; i < keys_length; i++) {
    srtp_master_key_t *key = unifex_alloc(sizeof(srtp_master_key_t));
    if (!key) {
      free_master_keys_array(policy);
      *err = unifex_raise(env, "not enough memory");
      return false;
    }

    key->key = keys[i]->data;
    key->mki_id = keys_mkis[i]->data;
    key->mki_size = keys_mkis[i]->size;

    policy->keys[i] = key;
  }

  return true;
}

UNIFEX_TERM create(UnifexEnv *env) {
  UnifexState *state = unifex_alloc_state(env);
  state->session = NULL;

  srtp_err_status_t err = srtp_create(&state->session, NULL);
  if (err) {
    unifex_release_state(env, state);
    return unifex_raise(env, srtp_util_strerror(err));
  }

  return create_result(env, state);
}

UNIFEX_TERM add_stream(UnifexEnv *env, UnifexState *state, int ssrc_type,
                       uint ssrc, UnifexPayload **keys,
                       unsigned int keys_length, UnifexPayload **keys_mkis,
                       unsigned int keys_mkis_length, char *rtp_crypto_profile,
                       char *rtcp_crypto_profile, uint window_size,
                       int allow_repeat_tx) {
  int err;
  srtp_err_status_t serr;
  UNIFEX_TERM uerr;

  srtp_policy_t policy;
  memset(&policy, 0, sizeof(srtp_policy_t));

  policy.window_size = window_size;
  policy.allow_repeat_tx = allow_repeat_tx;

  err = srtp_util_unmarshal_ssrc(ssrc_type, ssrc, &policy.ssrc);
  if (!err) {
    return unifex_raise_args_error(env, "ssrc", "invalid");
  }

  err = srtp_util_set_crypto_policy_from_crypto_profile_atom(rtp_crypto_profile,
                                                             &policy.rtp);
  if (!err) {
    return unifex_raise_args_error(env, "rtp", "invalid");
  }

  err = srtp_util_set_crypto_policy_from_crypto_profile_atom(
      rtcp_crypto_profile, &policy.rtcp);
  if (!err) {
    return unifex_raise_args_error(env, "rtcp", "invalid");
  }

  err = create_master_keys_array(env, keys, keys_length, keys_mkis,
                                 keys_mkis_length, &policy, &uerr);
  if (!err) {
    return uerr;
  }

  serr = srtp_add_stream(state->session, &policy);

  free_master_keys_array(&policy);

  if (serr) {
    return unifex_raise(env, srtp_util_strerror(serr));
  }

  return add_stream_result_ok(env);
}

UNIFEX_TERM remove_stream(UnifexEnv *env, UnifexState *state, uint ssrc) {
  // htonl below is required due to legacy reasons, see
  // https://github.com/cisco/libsrtp/issues/306
  srtp_err_status_t serr = srtp_remove_stream(state->session, htonl(ssrc));
  if (serr) {
    return unifex_raise(env, srtp_util_strerror(serr));
  }

  return remove_stream_result_ok(env);
}

UNIFEX_TERM protect(UnifexEnv *env, UnifexState *state, UnifexPayload *payload,
                    int use_mki, uint mki_index) {
  int err;
  srtp_err_status_t serr;

  UnifexPayload *protected = unifex_payload_clone_ex(
      env, payload, payload->type, payload->size + SRTP_MAX_TRAILER_LEN);
  int len = (int)payload->size;

  serr = srtp_protect_mki(state->session, protected->data, &len, use_mki,
                          mki_index);
  if (serr) {
    unifex_payload_release_ptr(&protected);
    return unifex_raise(env, srtp_util_strerror(serr));
  }

  err = unifex_payload_realloc(protected, len);
  if (!err) {
    unifex_payload_release_ptr(&protected);
    return unifex_raise(env, "failed to realloc protected payload");
  }

  UNIFEX_TERM res = protect_result_ok(env, protected);
  unifex_payload_release_ptr(&protected);
  return res;
}

UNIFEX_TERM unprotect(UnifexEnv *env, UnifexState *state,
                      UnifexPayload *payload, int use_mki) {
  int err;
  srtp_err_status_t serr;

  UnifexPayload *unprotected = unifex_payload_clone(env, payload);
  int len = (int)payload->size;

  serr = srtp_unprotect_mki(state->session, unprotected->data, &len, use_mki);
  if (serr) {
    unifex_payload_release_ptr(&unprotected);

    switch (serr) {
    case srtp_err_status_auth_fail:
      return unprotect_result_error_auth_fail(env);
    case srtp_err_status_replay_fail:
      return unprotect_result_error_replay_fail(env);
    case srtp_err_status_bad_mki:
      return unprotect_result_error_bad_mki(env);
    default:
      return unifex_raise(env, srtp_util_strerror(serr));
    }
  }

  err = unifex_payload_realloc(unprotected, len);
  if (!err) {
    unifex_payload_release_ptr(&unprotected);
    return unifex_raise(env, "failed to realloc unprotected payload");
  }

  UNIFEX_TERM res = unprotect_result_ok(env, unprotected);
  unifex_payload_release_ptr(&unprotected);
  return res;
}
