defmodule LibSRTP.Native do
  @moduledoc false

  use Unifex.Loader

  alias LibSRTP.{MasterKey, Policy}

  require LibSRTP

  @spec marshal_ssrc(LibSRTP.Policy.ssrc_pattern_t()) :: {ssrc_type :: 1..3, LibSRTP.ssrc_t()}
  def marshal_ssrc(:any_inbound), do: {2, 0}
  def marshal_ssrc(:any_outbound), do: {3, 0}
  def marshal_ssrc(ssrc) when LibSRTP.is_ssrc(ssrc), do: {1, ssrc}

  @spec marshal_master_keys(Policy.key_spec_t()) :: {keys :: [binary()], mkis :: [binary()]}
  def marshal_master_keys(key) when is_binary(key) do
    {[key], []}
  end

  def marshal_master_keys(keys) when is_list(keys) do
    keys
    |> Enum.map(fn %MasterKey{key: key, mki: mki} -> {key, mki} end)
    |> Enum.unzip()
  end
end
