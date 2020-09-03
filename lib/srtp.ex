defmodule SRTP do
  alias SRTP.{Native, Policy}

  require Record

  @opaque t :: {__MODULE__, reference}

  @type ssrc_t :: 0..4_294_967_295

  defguard is_ssrc(ssrc) when ssrc in 0..4_294_967_295

  defmacrop ref(native) do
    quote do
      {unquote(__MODULE__), unquote(native)}
    end
  end

  @spec new() :: t()
  def new() do
    ref(Native.create())
  end

  @spec add_stream(t(), policy :: Policy.t()) :: :ok
  def add_stream(ref(state), %Policy{} = policy) do
    {ssrc_type, ssrc} = Native.marshal_ssrc(policy.ssrc)
    {keys, keys_mkis} = Native.marshal_master_keys(policy.key)

    Native.add_stream(
      state,
      ssrc_type,
      ssrc,
      keys,
      keys_mkis,
      policy.rtp,
      policy.rtcp,
      policy.window_size,
      policy.allow_repeat_tx
    )
  end

  @spec remove_stream(t(), ssrc :: ssrc_t()) :: :ok
  def remove_stream(ref(state), ssrc) when is_ssrc(ssrc) do
    Native.remove_stream(state, ssrc)
  end

  @spec protect(t(), unprotected :: binary(), mki_index :: pos_integer() | nil) ::
          {:ok, protected :: binary()}
  def protect(srtp, unprotected, mki_index \\ nil)

  def protect(ref(state), unprotected, nil) do
    Native.protect(state, :rtp, unprotected, false, 0)
  end

  def protect(ref(state), unprotected, mki_index) when is_integer(mki_index) do
    Native.protect(state, :rtp, unprotected, true, mki_index)
  end

  @spec protect_rtcp(t(), unprotected :: binary(), mki_index :: pos_integer() | nil) ::
          {:ok, protected :: binary()}
  def protect_rtcp(srtp, unprotected, mki_index \\ nil)

  def protect_rtcp(ref(state), unprotected, nil) do
    Native.protect(state, :rtcp, unprotected, false, 0)
  end

  def protect_rtcp(ref(state), unprotected, mki_index) when is_integer(mki_index) do
    Native.protect(state, :rtcp, unprotected, true, mki_index)
  end

  @spec unprotect(t(), protected :: binary(), use_mki :: boolean()) ::
          {:ok, unprotected :: binary()} | {:error, :auth_fail | :reply_fail | :bad_mki}
  def unprotect(ref(state), protected, use_mki \\ false) do
    Native.unprotect(state, :rtp, protected, use_mki)
  end

  @spec unprotect_rtcp(t(), protected :: binary(), use_mki :: boolean()) ::
          {:ok, unprotected :: binary()} | {:error, :auth_fail | :reply_fail | :bad_mki}
  def unprotect_rtcp(ref(state), protected, use_mki \\ false) do
    Native.unprotect(state, :rtcp, protected, use_mki)
  end
end
