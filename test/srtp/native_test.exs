defmodule SRTP.NativeTest do
  use ExUnit.Case

  alias SRTP.Native

  test "creates successfully" do
    native = Native.create()
    assert is_reference(native)
  end

  test "adds and removes stream successfully" do
    ssrc = 123_456_789

    native = Native.create()

    assert :ok ==
             Native.add_stream(
               native,
               1,
               ssrc,
               [
                 <<1, 2, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                   0, 0, 0, 0>>
               ],
               [],
               :rtp_default,
               :rtcp_default,
               0,
               false
             )

    assert :ok == Native.remove_stream(native, ssrc)
  end
end
