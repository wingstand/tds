defmodule Tds.TlsWrapper do
  use GenServer
  require Logger

  @header_length 8

  defstruct socket: nil, controlling_process: nil, recv_buffer: <<>>, negotiated?: false

  def start_link(socket) do
    GenServer.start_link __MODULE__, %__MODULE__{socket: socket}
  end

  def init(%__MODULE__{socket: sock} = wrapper) do
    Port.connect sock, self()

    {:ok, wrapper}
  end

  def handle_info(:negotiated, wrapper) do
    {:noreply, %{wrapper | negotiated?: true}}
  end

  def handle_info({:controlling_process, pid}, state) do
    {:noreply, %{state | controlling_process: pid}}
  end

  def handle_info({:send, packet}, %__MODULE__{negotiated?: false, socket: socket} = wrapper) do
    length = IO.iodata_length(packet) + @header_length
    header = <<0x12, 1, length::size(16), 0::size(16), 1, 0>>

    :gen_tcp.send socket, header
    :gen_tcp.send socket, packet

    {:noreply, wrapper}
  end

  def handle_info({:send, packet}, %__MODULE__{negotiated?: true, socket: socket} = wrapper) do
    :gen_tcp.send socket, packet

    {:noreply, wrapper}
  end

  def handle_info({:tcp, port, data}, %__MODULE__{negotiated?: false, recv_buffer: recv_buffer, controlling_process: pid} = wrapper) do
    {packets, remaining} = process_recv_buffer recv_buffer <> data

    Enum.each packets, fn packet ->
      Kernel.send pid, {:tcp, port, packet}
    end

    if remaining > 0 do
      setopts port, [{:active, :once}]
    end

    {:noreply, %{wrapper | recv_buffer: remaining}}
  end

  def handle_info({:tcp, _port, _data} = info, %__MODULE__{negotiated?: true, controlling_process: pid} = wrapper) do
    Kernel.send pid, info

    {:noreply, wrapper}
  end

  def handle_info({:tcp_closed, _port} = info, %__MODULE__{controlling_process: pid} = wrapper) do
    Logger.debug "Received tcp closed"

    Kernel.send pid, info

    {:noreply, wrapper}
  end

  defp process_recv_buffer(buffer = <<_type::size(8), _status::size(8), length::size(16), _channel::size(16), _id::size(8), _window::size(8), data::binary>>) do
    if length <= :erlang.byte_size(buffer) do
      data_length = length - @header_length
      packet = :binary.part data, 0, data_length
      remaining = :binary.part data, data_length, (:erlang.byte_size(data) - data_length)
      {packets, partial} = process_recv_buffer remaining
      {[packet | packets], partial}
    else
      {[], buffer}
    end
  end

  defp process_recv_buffer(buffer) do
    {[], buffer}
  end

  defp send_message(socket, msg) do
    {:connected, pid} = Port.info socket, :connected
    Kernel.send pid, msg
    :ok
  end

  # Callbacks used by the :ssl library as we're acting as the connection's transport

  def getopts(socket, options) do
    :inet.getopts socket, options
  end

  def setopts(socket, options) do
    :inet.setopts socket, options
  end

  def peername(socket) do
    :inet.peername socket
  end

  def controlling_process(socket, pid) do
    send_message socket, {:controlling_process, pid}
  end

  def send(socket, packet) do
    send_message socket, {:send, packet}
  end

  def recv(_socket, _length, _timeout \\ :infinity) do
    raise "recv not supported"
  end
end
