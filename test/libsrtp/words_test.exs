defmodule LibSRTP.WordsTest do
  use ExUnit.Case, async: true

  alias Support.SamplePacket

  setup do
    {master_key, encrypted} = SamplePacket.load!("words_encrypted.txt")
    {nil, decrypted} = SamplePacket.load!("words_decrypted.txt")

    srtp = LibSRTP.new()
    ssrc = 0xDEADBEEF
    policy = %LibSRTP.Policy{ssrc: ssrc, key: master_key}
    :ok = LibSRTP.add_stream(srtp, policy)
    on_exit(fn -> LibSRTP.remove_stream(srtp, ssrc) end)

    [
      master_key: master_key,
      encrypted: encrypted,
      decrypted: decrypted,
      policy: policy,
      srtp: srtp
    ]
  end

  test "decoding words stream", ctx do
    for {e, d} <- Enum.zip(ctx.encrypted, ctx.decrypted) do
      assert {:ok, d} == LibSRTP.unprotect(ctx.srtp, e)
    end
  end

  test "encoding words stream", ctx do
    for {e, d} <- Enum.zip(ctx.encrypted, ctx.decrypted) do
      assert {:ok, e} == LibSRTP.protect(ctx.srtp, d)
    end
  end
end