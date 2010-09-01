module RIP
end

class RIP::IP
  class IPError < Exception; end

  attr_reader :subnet

  def initialize(ip_addr, subnet = nil)
    @ip_addr = ip_addr
    @subnet  = subnet || detect_ip_class
  end

  def detect_ip_class
    case
    when @ip_addr & 0x80000000 == 0
      8
    when @ip_addr & 0xc0000000 == 0x80000000
      16
    when @ip_addr & 0xe0000000 == 0xc0000000
      24
    else
      4
    end
  end

  def to_s
    [@ip_addr].pack("N").unpack("C4").map{|a| a.to_s}*"." + "/#{@subnet}"
  end

  def self.from_s(ip)
    ip, subnet = ip.split('/')
    subnet = subnet.to_i
    new(pack(ip), subnet)
  end

  def to_i
    @ip_addr
  end

  def self.pack(ip)
    ip.split('.', 4).
       map { |i| Integer(i) }.
       tap { |a| raise IPError, "must have 4 numbers" unless a.size == 4 }.
       tap { |a| raise IPError, "must be between 0 and 255" unless a.all? { |i| (0..255).include?(i) } }.
       pack("C4").unpack("N").first
  end

end

module RIP::Protocol
  extend self
  class PacketError < Exception; end

  class Packet
    include RIP

    attr_accessor :version, :nodes

    def initialize(host, version = 2)
      @version = version
      @host = host
      @nodes = []
    end

    def self.unpack(data, host)
      cmd, ver, zero = data.unpack("CCn")

      raise PacketError, "Only RIPv1 and RIPv2 packets are supported" unless [1,2].include?(ver)
      raise PacketError, "The third and forth bytes must be zero" unless zero == 0
      raise PacketError, "Command should be either 1 or 2" unless [1, 2].include?(cmd)
      raise PacketError, "Entry size should be upto 25 entries" if (data.size - 4) % 20 !=0 || (data.size - 4) > 500

      COMMANDS[cmd].new(host, ver).tap { |obj| obj.unpack_entries(data) }
    end

    def unpack_entries(data)
      meth = method(:unpack_entry_v1) if version == 1
      meth = method(:unpack_entry_v2) if version == 2
      number = (data.size - 4) / 20
      number.times do |i|
        begin
          @nodes << meth.call(i, data[(4 + i*20)..(24 + i*20)])
        rescue PacketError #RFC 2453 page 27
          Ripper::logger.info{ "unpack entry error:\n#{data[(4 + i*20)..(24 + i*20)].inspect}" } unless ENV['test']
        end
      end
    end

    def unpack_entry_v1(i, data)
      family, zero1, ip, zero2, zero3, metric = data.unpack("nnNNNN")

      raise PacketError, "#{zero1} should be zero" unless zero1 == 0
      raise PacketError, "#{zero2} should be zero" unless zero2 == 0
      raise PacketError, "#{zero3} should be zero" unless zero3 == 0
      raise PacketError, "metric should be between 0 and 16 inclusive" unless (1..16).include?(metric)

      RIP::RouteTable::Node.new(@host, family, IP.new(ip), metric)
    end

    def unpack_entry_v2(i, data)
      family, route_tag, ip, subnet, next_hop, metric = data.unpack("nnNNNN")

      raise PacketError, "metric should be between 0 and 16 inclusive" unless (0..16).include?(metric)

      RIP::RouteTable::Node.new(@host, family, IP.new(ip, subnet), metric, :route_tag => route_tag, :next_hop => next_hop)
    end
  end

  class Request < Packet
    def response?
      false
    end

    def request?
      true
    end

    def send_entire_table?
      nodes.size == 1 && nodes.first.metric == 16 && nodes.first.family == 0
    end
  end

  class Response < Packet
    def response?
      true
    end

    def request?
      false
    end

    def self.pack(nodes, version = 2)
      data = [2,version,0].pack("CCn") #always response
      meth = method(:pack_entry_v1) if version == 1
      meth = method(:pack_entry_v2) if version == 2
      nodes.each do |node|
        data += meth.call(node)
      end
      data
    end

    def self.pack_entry_v1(node)
      [node.family,0,node.ip,0,0,node.metric].pack("nnNNNN")
    end

    def self.pack_entry_v2(node)
      [node.family, node.route_tag, node.ip.to_i, node.subnet, node.next_hop, node.metric].pack("nnNNNN")
    end
  end

  class Packet; COMMANDS = [nil, Request, Response].freeze; end

  def parse(data, host)
    Packet.unpack(data, host)
  end

  def pack_answer(nodes, version = 2)
    return if nodes.size == 0
    answer = []
    0.step(nodes.size, 25) do |i|
      ns = nodes[i...(i+25)]
      answer << Response.pack(ns)
    end
    answer
  end

#  module_function :parse
end
require 'thread'

class RIP::RouteTable
  attr_reader :nodes

  INFINITY_METRIC = 16

  def initialize
    @mutex = Mutex.new

    @nodes = {}
    Ripper::Config.local_route_table.each do |ip|
      ip = RIP::IP.from_s(ip)

      self << Node.new(Ripper::Config.host, 2, ip, -1, :local => true)
    end
  end

  def collect_garbage
    changed = false
    @mutex.synchronize do
      remove_at = Time.now - 120
      changed = @nodes.reject! { |k,v| !v.local? && v.created_at <= remove_at }
    end
    if changed
      RIP::Protocol.pack_answer(Ripper.route_table.expose).each do |answer|
        Ripper.connection.send_multicast answer
      end
    end
  end

  def amnesia
    @mutex.synchronize do
      @nodes = {}
    end
  end

  def <<(node)
    #@nodes.delete_if { |k,v| v.ip == node.ip }
    @mutex.synchronize do
      @nodes[node.ip.to_i] = node
    end
  end
  alias_method 'add_node', '<<'

  def eat_packet(packet)
    packet.nodes.each do |node|
      skip_add = @nodes[node.ip.to_i].metric < node.metric rescue nil
      self << node unless skip_add
    end
    dump_table
  end

  def expose
    @nodes.values.freeze
  end

  def serve_request(packet)
    if packet.send_entire_table?
      @nodes.values.freeze
    else
      packet.nodes.map do |node|
        @nodes[node.ip.to_i]
      end.compact
    end
  end

  def dump_table
    puts "%20s | %20s | Metric" % ["IP", "via"]
    puts "-"*(20+20+12)
    @nodes.each do |k,node|
      puts "%20s | %20s | %d" % [node.ip.to_s, node.host.to_s, node.metric]
    end
    puts "-"*(20+20+12)
    puts
  end

  class Node
    attr_accessor :created_at, :host, :metric
    attr_reader :ip, :family, :route_tag, :next_hop

    def initialize(host, family, ip, metric, options = {})
      @created_at = Time.now
      @ip = ip
      @host = host
      @metric = [metric + 1, INFINITY_METRIC].min
      @family = family # IP = 2
      @route_tag = options[:route_tag] || 0
      @next_hop  = options[:next_hop] || 0
      @local = options[:local] || false
    end

    def local?
      @local
    end

    def subnet
      @ip.subnet
    end
  end
end
