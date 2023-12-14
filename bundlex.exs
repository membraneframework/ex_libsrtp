defmodule Membrane.ExLibSRTP.BundlexProject do
  use Bundlex.Project

  def project do
    [
      natives: natives()
    ]
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
        os_deps: [
          libsrtp2: [
            {:precompiled, Membrane.PrecompiledDependencyProvider.get_dependency_url(:srtp)},
            :pkg_config
          ]
        ],
        preprocessor: Unifex
      ]
    ]
  end
end
