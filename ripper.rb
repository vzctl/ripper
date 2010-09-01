$KCODE='u'
$:.unshift File.join(File.dirname(__FILE__))

require 'rubygems'
require 'rip'
module Ripper
  extend self
  attr_reader :connection

  def logger
    @logger ||= Logger.new(STDOUT)
  end

  def root
    @root ||= File.join(File.dirname(__FILE__), '..')
  end

  def route_table
    @route_table ||= RIP::RouteTable.new
  end

  def start
    @connection = Ripper::Connection.new
    thr = Thread.fork { @connection.subscribe_to_multicast }
    Ripper::Timer.new(42) { Ripper.route_table.collect_garbage }
    Ripper::Timer.new(30) do
      RIP::Protocol.pack_answer(Ripper.route_table.expose).each do |answer|
        @connection.send_multicast answer
      end
    end
    thr.join
  end
end
class Ripper::Config
  class <<self
    def define
      yield proxy_object
    end

    def method_missing(*args)
      proxy_object.send(*args)
    end

    def proxy_object
      @proxy_object ||= ProxyObject.new
    end
    private :proxy_object
  end

  class ProxyObject
    def initialize
      @hash = {}
    end

    def method_missing(method, *args)
      method = method.to_s
      if method =~ /=$/ && args.size == 1
        @hash[method[0..-2].intern] = args[0]
      elsif args.size == 0
        @hash[method.intern] ||= ProxyObject.new
      elsif args.size == 1
        @hash[method.intern] = args[0]
      else
        raise ArgumentError
      end
    end
  end
end
require "socket"
require 'ipaddr'

class Ripper::Connection
  PORT = 5200
  # PORT = 520 # requires root!
  TTL  = 2

  def subscribe_to_multicast
    ip =  IPAddr.new("224.0.0.9").hton + IPAddr.new("0.0.0.0").hton
    @socket = UDPSocket.new
    @socket.setsockopt(Socket::IPPROTO_IP, Socket::IP_ADD_MEMBERSHIP, ip)
    @socket.bind(Socket::INADDR_ANY, PORT)
    # @socket.bind(Socket::INADDR_ANY, 520)

    loop do
      data, info = @socket.recvfrom(1024)
      # puts "MSG: #{data} from #{info[2]} (#{info[3]})/#{info[1]} len #{data.size}"
      @info = info
      receive_data(data)
    end
  rescue Exception => e
    puts e.message
    raise e
  end

  def send_data(data)
    sock = UDPSocket.open
    sock.send(data, 0, @info[2], @info[1])
  end

  def send_multicast(data)
    return unless data
    begin
      socket = UDPSocket.open
      socket.setsockopt(Socket::IPPROTO_IP, Socket::IP_TTL, [TTL].pack('i'))
      socket.send(data, 0, "224.0.0.9", PORT)
    ensure
      socket.close
    end
  rescue Exception => e
    puts e.message
    raise e
  end

  def receive_data(data)
    packet = RIP::Protocol.parse(data, @info[2])
    if packet.request?
      Ripper.route_table.serve_request(packet).each do |answer|
        send_data RIP::Protocol.pack_answer(answer, packet.version)
      end
    else
      Ripper.route_table.eat_packet(packet)
    end
  rescue RIP::Protocol::PacketError
    Ripper.logger.info {"wrong packet:\n#{data.inspect}"}
  end
 end

class Ripper::Timer
  def initialize(time, &block)
    @block = block
    @time = time
    Thread.fork { go }
  end

  def go
    loop do
      begin
        @block.call
        sleep(@time)
      rescue Exception => e
        puts e.message
        puts e.backtrace
      end
    end
  end
  private :go
end

class Object
  def returning(obj)
    yield obj
    obj
  end unless Object.respond_to? :returning

  def tap
    yield self
    self
  end unless Object.respond_to? :tap
end
