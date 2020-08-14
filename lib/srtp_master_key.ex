defmodule SRTP.MasterKey do
  @type t :: %__MODULE__{
          key: binary(),
          mki: binary()
        }

  @enforce_keys [:key, :mki]
  defstruct @enforce_keys
end
