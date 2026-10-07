defmodule ExLibSRTP.StreamROCTest do
  use ExUnit.Case, async: true

  # 30-byte master key (16 key + 14 salt) for the default
  # aes_cm_128_hmac_sha1_80 profile.
  @key <<193, 238, 195, 113, 125, 167, 97, 149, 187, 135, 133, 120, 121, 10, 247, 28, 78, 233,
         248, 89, 225, 151, 164, 20, 167, 141, 90, 188, 116, 81>>
  @ssrc 0x00C0FFEE

  defp rtp(seq, ts \\ 96_000) do
    <<2::2, 0::1, 0::1, 0::4, 0::1, 120::7, seq::16, ts::32, @ssrc::32, "payload"::binary>>
  end

  defp context_with_stream do
    srtp = ExLibSRTP.new()
    :ok = ExLibSRTP.add_stream(srtp, %ExLibSRTP.Policy{ssrc: @ssrc, key: @key})
    srtp
  end

  describe "set_stream_roc/3 and get_stream_roc/2" do
    test "set ROC takes effect on the next processed packet" do
      srtp = context_with_stream()
      assert {:ok, 0} = ExLibSRTP.get_stream_roc(srtp, @ssrc)
      assert :ok = ExLibSRTP.set_stream_roc(srtp, @ssrc, 5)
      assert {:ok, _} = ExLibSRTP.protect(srtp, rtp(1000))
      assert {:ok, 5} = ExLibSRTP.get_stream_roc(srtp, @ssrc)
    end

    test "unknown ssrc yields an {:error, reason} tuple" do
      srtp = context_with_stream()
      assert {:error, :bad_param} = ExLibSRTP.get_stream_roc(srtp, @ssrc + 1)
      assert {:error, :bad_param} = ExLibSRTP.set_stream_roc(srtp, @ssrc + 1, 1)
    end

    test "a receiver cannot decrypt a ROC-1 sender until it adopts the ROC" do
      sender = context_with_stream()
      # Outbound index ROC=1, seq=1000.
      assert :ok = ExLibSRTP.set_stream_roc(sender, @ssrc, 1)
      packet = rtp(1000)
      assert {:ok, protected} = ExLibSRTP.protect(sender, packet)

      receiver = context_with_stream()
      assert {:error, :auth_fail} = ExLibSRTP.unprotect(receiver, protected)
      assert :ok = ExLibSRTP.set_stream_roc(receiver, @ssrc, 1)
      assert {:ok, ^packet} = ExLibSRTP.unprotect(receiver, protected)
    end
  end

  describe "ROC discovery scan" do
    # Simulates stream failover where sender is already past ROC 0
    test "scan finds the ROC of a sender past its first wrap" do
      sender = context_with_stream()

      # Fill ROC 0 (seq 0..65_535), then the next packet wraps: ROC 1, seq 0.
      for seq <- 0..65_535, reduce: nil do
        _acc ->
          {:ok, p} = ExLibSRTP.protect(sender, rtp(seq))
          p
      end

      assert {:ok, wrapped_packet} = ExLibSRTP.protect(sender, rtp(0))
      assert {:ok, 1} = ExLibSRTP.get_stream_roc(sender, @ssrc)

      receiver = context_with_stream()

      scan =
        Enum.find_value(0..2, fn roc ->
          :ok = ExLibSRTP.set_stream_roc(receiver, @ssrc, roc)

          case ExLibSRTP.unprotect(receiver, wrapped_packet) do
            {:ok, _} -> roc
            {:error, _} -> nil
          end
        end)

      assert scan == 1
    end
  end
end
