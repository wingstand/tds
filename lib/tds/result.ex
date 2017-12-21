defmodule Tds.Result do
  @moduledoc """
  Result struct returned from any successful query.

  ## Fields

  * `columns`: The column names.
  * `rows`: The result set as a list of tuples. Each tuple corresponds to a
            row, while each element in the tuple corresponds to a column.
  * `num_rows`: The number of fetched or affected rows.
  """

  @typedoc "The result of a database query."
  @type t :: %__MODULE__{
          columns: [String.t()] | nil,
          rows: [tuple] | nil,
          num_rows: integer,
          types: [atom]
        }

  defstruct [:columns, :rows, :num_rows, :types]
end
