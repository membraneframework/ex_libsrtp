defmodule SRTP.WordsTest do
  use ExUnit.Case, async: true

  alias Support.SamplePacket

  setup do
    {master_key, encrypted} = SamplePacket.load!("words_encrypted.txt")
    {nil, decrypted} = SamplePacket.load!("words_decrypted.txt")

    srtp = SRTP.new()

    policy = %SRTP.Policy{
      ssrc: 0xDEADBEEF,
      key: master_key
    }

    SRTP.add_stream(srtp, policy)

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
      assert {:ok, d} == SRTP.unprotect(ctx.srtp, e)
    end
  end

  test "encoding words stream", ctx do
    for {e, d} <- Enum.zip(ctx.encrypted, ctx.decrypted) do
      assert {:ok, e} == SRTP.protect(ctx.srtp, d)
    end
  end
end
