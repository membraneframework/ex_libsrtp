defmodule Membrane.ExLibSRTP.BundlexProject do
  use Bundlex.Project

  def project do
    [
      natives: natives()
    ]
  end

  defp get_srtp_url() do
    url_prefix =
      "https://github.com/membraneframework-precompiled/precompiled_libsrtp/releases/latest/download/srtp"

    case Bundlex.get_target() do
      %{os: "linux"} -> "#{url_prefix}_linux.tar.gz"
      %{architecture: "x86_64", os: "darwin" <> _rest} -> "#{url_prefix}_macos_intel.tar.gz"
      %{architecture: "aarch64", os: "darwin" <> _rest} -> "#{url_prefix}_macos_arm.tar.gz"
      _other -> nil
    end
  end

  defp natives() do
    [
      srtp: [
        interface: :nif,
        sources: [
          "srtp.c",
          "srtp_util.c",
          "unifex_util.c"
        ],
        os_deps: [libsrtp2: [{:precompiled, get_srtp_url()}, :pkg_config]],
        preprocessor: Unifex
      ]
    ]
  end
end
