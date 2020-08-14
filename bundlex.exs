defmodule Membrane.Element.Template.BundlexProject do
  use Bundlex.Project

  def project do
    [
      natives: natives(Bundlex.platform())
    ]
  end

  defp natives(_platform) do
    [
      srtp: [
        interface: :nif,
        sources: ["srtp.c", "_generated/nif/srtp.c"],
        deps: [unifex: :unifex],
        pkg_configs: ["libsrtp2"]
      ]
    ]
  end
end
