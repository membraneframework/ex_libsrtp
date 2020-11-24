defmodule ExLibSRTP.NativeTest do
  use ExUnit.Case

  alias ExLibSRTP.Native

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

  test "updates stream successfully" do
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

    assert :ok ==
             Native.update(
               native,
               1,
               ssrc,
               [
                 <<14, 51, 84, 241, 9, 172, 84, 201, 217, 97, 188, 6, 111, 0, 234, 162, 196, 41,
                   66, 190, 185, 135, 28, 183, 160, 103, 53, 219, 225, 43>>
               ],
               [],
               :rtp_default,
               :rtcp_default,
               0,
               false
             )
  end
end
