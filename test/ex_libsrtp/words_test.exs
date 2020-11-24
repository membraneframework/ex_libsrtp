defmodule ExLibSRTP.WordsTest do
  use ExUnit.Case, async: true

  alias Support.SamplePacket

  setup do
    {master_key, encrypted} = SamplePacket.load!("words_encrypted.txt")
    {nil, decrypted} = SamplePacket.load!("words_decrypted.txt")

    srtp = ExLibSRTP.new()
    ssrc = 0xDEADBEEF
    policy = %ExLibSRTP.Policy{ssrc: ssrc, key: master_key}
    :ok = ExLibSRTP.add_stream(srtp, policy)
    on_exit(fn -> ExLibSRTP.remove_stream(srtp, ssrc) end)

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
      assert {:ok, d} == ExLibSRTP.unprotect(ctx.srtp, e)
    end
  end

  test "encoding words stream", ctx do
    for {e, d} <- Enum.zip(ctx.encrypted, ctx.decrypted) do
      assert {:ok, e} == ExLibSRTP.protect(ctx.srtp, d)
    end
  end
end
