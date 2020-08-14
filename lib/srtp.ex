defmodule SRTP do
  alias SRTP.{Native, Policy}

  @opaque t :: {__MODULE__, any()}

  @type ssrc_t :: Policy.ssrc_t()

  @spec is_ssrc(any) :: {:__block__ | {:., [], [:erlang | :is_integer, ...]}, [], [...]}
  defguard is_ssrc(ssrc) when is_integer(ssrc)

  defmacrop ref(native) do
    quote do
      {unquote(__MODULE__), unquote(native)}
    end
  end

  @spec new :: t()
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
          Bunch.Type.try_t(protected :: binary())
  def protect(srtp, unprotected, mki_index \\ nil)

  def protect(ref(state), unprotected, nil) do
    Native.protect(state, unprotected, false, 0)
  end

  def protect(ref(state), unprotected, mki_index) when is_integer(mki_index) do
    Native.protect(state, unprotected, true, mki_index)
  end

  @spec unprotect(t(), protected :: binary(), use_mki :: boolean()) ::
          Bunch.Type.try_t(unprotected :: binary())
  def unprotect(srtp, protected, use_mki \\ false)

  def unprotect(ref(state), protected, use_mki) do
    Native.unprotect(state, protected, use_mki)
  end
end
