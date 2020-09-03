module(SRTP.Native)

state_type("State")

callback(:load, :on_load)
callback(:unload, :on_unload)

spec(create() :: state)

# typedef enum {
#   ssrc_specific = 1,
#   ssrc_any_inbound = 2,
#   ssrc_any_outbound = 3
# } srtp_ssrc_type_t;

spec(
  add_stream(
    state,
    ssrc_type :: int,
    ssrc :: unsigned,
    keys :: [payload],
    keys_mkis :: [payload],
    rtp_crypto_profile :: atom,
    rtcp_crypto_profile :: atom,
    window_size :: unsigned,
    allow_repeat_tx :: bool
  ) :: :ok :: label
)

spec(remove_stream(state, ssrc :: unsigned) :: :ok :: label)

spec(protect(state, payload, use_mki :: bool, mki_index :: unsigned) :: {:ok :: label, payload})

spec(
  unprotect(state, payload, use_mki :: bool) ::
    {:ok :: label, payload}
    | {:error :: label, :auth_fail :: label}
    | {:error :: label, :replay_fail :: label}
    | {:error :: label, :bad_mki :: label}
)
