#include "srtp_util.h"

const char *srtp_strerror(srtp_err_status_t err) {
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
