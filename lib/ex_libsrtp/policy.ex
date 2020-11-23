defmodule ExLibSRTP.Policy do
  @moduledoc """
  Policy for setting up SRTP stream configuration.

  For meaning of particular fields, please refer to ExLibSRTP documentation.
  """

  # TODO: add EKT, enc_xtn_hdr

  alias ExLibSRTP.MasterKey

  @type ssrc_pattern_t :: ExLibSRTP.ssrc_t() | :any_inbound | :any_outbound

  @type crypto_profile_t ::
          :rtp_default
          | :rtcp_default
          | :aes_cm_128_hmac_sha1_80
          | :aes_cm_128_hmac_sha1_32
          | :aes_cm_128_null_auth
          | :null_cipher_hmac_sha1_80
          | :null_cipher_hmac_null
          | :aes_cm_256_hmac_sha1_80
          | :aes_cm_256_hmac_sha1_32
          | :aes_cm_256_null_auth
          | :aes_cm_192_hmac_sha1_80
          | :aes_cm_192_hmac_sha1_32
          | :aes_cm_192_null_auth
          | :aes_gcm_128_8_auth
          | :aes_gcm_256_8_auth
          | :aes_gcm_128_8_only_auth
          | :aes_gcm_256_8_only_auth
          | :aes_gcm_128_16_auth
          | :aes_gcm_256_16_auth

  @type key_spec_t :: binary() | [MasterKey.t()]

  @type t :: %__MODULE__{
          ssrc: ssrc_pattern_t,
          key: key_spec_t(),
          rtp: crypto_profile_t(),
          rtcp: crypto_profile_t(),
          window_size: pos_integer(),
          allow_repeat_tx: boolean()
        }

  @enforce_keys [:ssrc, :key]
  defstruct @enforce_keys ++
              [
                rtp: :rtp_default,
                rtcp: :rtcp_default,
                window_size: 0,
                allow_repeat_tx: false
              ]

  @doc """
  Relevant specification: https://www.iana.org/assignments/srtp-protection/srtp-protection.xhtml
  """
  @spec crypto_profile_from_dtls_srtp_protection_profile(
          value :: pos_integer() | {pos_integer(), pos_integer()}
        ) :: {:ok, crypto_profile_t()} | :error
  def crypto_profile_from_dtls_srtp_protection_profile(0x01), do: {:ok, :aes_cm_128_hmac_sha1_80}
  def crypto_profile_from_dtls_srtp_protection_profile(0x02), do: {:ok, :aes_cm_128_hmac_sha1_32}
  def crypto_profile_from_dtls_srtp_protection_profile(0x05), do: {:ok, :null_cipher_hmac_sha1_80}
  # null_cipher_hmac_sha1_32 is not supported in libsrtp2
  def crypto_profile_from_dtls_srtp_protection_profile(0x06), do: :error
  def crypto_profile_from_dtls_srtp_protection_profile(0x07), do: {:ok, :aes_gcm_128_16_auth}
  def crypto_profile_from_dtls_srtp_protection_profile(0x08), do: {:ok, :aes_gcm_256_16_auth}

  def crypto_profile_from_dtls_srtp_protection_profile(b) when is_number(b) do
    :error
  end

  def crypto_profile_from_dtls_srtp_protection_profile({0x00, b}) when is_number(b) do
    crypto_profile_from_dtls_srtp_protection_profile(b)
  end

  def crypto_profile_from_dtls_srtp_protection_profile({a, b})
      when is_number(a) and is_number(b) do
    :error
  end
end
