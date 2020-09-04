defmodule LibSRTPTest do
  use ExUnit.Case, async: true

  test "protect and unprotect rtcp" do
    srtp = LibSRTP.new()
    ssrc = 0xDEADBEEF

    master_key =
      <<193, 238, 195, 113, 125, 167, 97, 149, 187, 135, 133, 120, 121, 10, 247, 28, 78, 233, 248,
        89, 225, 151, 164, 20, 167, 141, 90, 188, 116, 81>>

    policy = %LibSRTP.Policy{ssrc: ssrc, key: master_key}
    assert :ok = LibSRTP.add_stream(srtp, policy)
    on_exit(fn -> LibSRTP.remove_stream(srtp, ssrc) end)

    rtcp =
      <<128, 200, 0, 6, 222, 173, 190, 239, 225, 250, 146, 5, 57, 219, 34, 204, 33, 31, 38, 192,
        0, 0, 0, 158, 0, 0, 108, 195>>

    assert {:ok, protected} = LibSRTP.protect_rtcp(srtp, rtcp)

    assert protected ==
             <<128, 200, 0, 6, 222, 173, 190, 239, 175, 92, 116, 163, 149, 247, 58, 210, 44, 89,
               189, 153, 0, 182, 102, 11, 56, 80, 211, 76, 128, 0, 0, 1, 173, 117, 100, 136, 130,
               76, 47, 37, 61, 151>>

    assert {:ok, unprotected} = LibSRTP.unprotect_rtcp(srtp, protected)
    assert unprotected == rtcp
  end
end
