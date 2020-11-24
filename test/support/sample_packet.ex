defmodule Support.SamplePacket do
  @moduledoc false

  @fixture_base_dir "test/fixtures/packets"

  @spec load!(name :: String.t()) :: {master_key :: binary() | nil, packets :: [binary()]}
  def load!(name) do
    lines =
      Path.join(@fixture_base_dir, name)
      |> File.read!()
      |> String.split(~r{\W}, trim: true)

    {master_key, lines} =
      case lines do
        ["MASTER_KEY", master_key | lines] -> {master_key, lines}
        lines -> {nil, lines}
      end

    master_key =
      case master_key do
        nil -> nil
        s -> from_hex_single!(s)
      end

    lines = Enum.map(lines, &from_hex_single!/1)

    {master_key, lines}
  end

  defp from_hex_single!(hex) do
    hex
    |> String.trim()
    |> Base.decode16!(case: :mixed)
  end
end
