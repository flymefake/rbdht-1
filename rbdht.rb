require "securerandom"
require "digest/sha1"
require "socket"
require "monitor"

require "bencode"

#DHT Constants
BOOTSTRAP_NODES = [
    ["router.bittorrent.com", 6881],
    ["dht.transmissionbt.com", 6881],
]
TID_LENGTH = 2
RE_JOIN_DHT_INTERVAL = 3
TOKEN_LENGTH = 2


module Utils
    def Utils.random_id
        Digest::SHA1.digest(SecureRandom.random_bytes(20))
    end

    def Utils.decode_nodes(nodes)
        n = []
        length = nodes.length
        if (length % 26) != 0
            return n
        end
        (0...length).step(26) do |i|
            nid = nodes[i...i+20]
            ip = nodes[i+20...i+24].unpack("CCCC").join(".")
            port = nodes[i+24...i+26].unpack("n")[0]
            n.push({"address" => [ip, port], "nid" => nid})
        end
        n
    end

    def Utils.gen_nearest_nid(target, nid)
        target[0..9] + nid[10..-1]
    end
end


module Crawler
    class DHTClient
        def initialize
            @nid = Utils::random_id
        end

        protected
        def join_DHT
            BOOTSTRAP_NODES.each do |address|
                send_find_node(address)
            end
        end

        def send_krpc(msg, address)
            begin
                @udf.send(msg.bencode, 0, address[0], address[1])
            rescue StandardError
            end
        end

        def send_find_node(address, nid=nil)
            nid = (nid != nil) ? Utils::gen_nearest_nid(nid, @nid) : @nid
            tid = SecureRandom.random_bytes(TID_LENGTH)
            msg = {
                "t" => tid,
                "y" => "q",
                "q" => "find_node",
                "a" => {
                    "id" => nid,
                    "target" => Utils::random_id
                }
            }
            send_krpc(msg, address)
        end

        def re_join_DHT
            Thread.new do
                loop do
                    empty = false
                    @node_pool.synchronize do
                        empty = @node_pool.empty?
                    end
                    join_DHT if empty
                    sleep(RE_JOIN_DHT_INTERVAL)
                end
            end
        end

        def auto_send_find_node
            loop do
                node = nil
                @node_pool.synchronize do
                    break if @node_pool.empty?
                    node = @node_pool.shift
                end
                send_find_node(node["address"], node["nid"]) if node != nil
                sleep(1.0 / @node_poll_max)
            end
        end

        def process_find_node_response(msg, address)
            begin
                Utils::decode_nodes(msg.fetch("r").fetch("nodes")).each do |node|
                    @node_pool.synchronize do
                        ip, port = node['address']
                        break unless port.between?(1, 65535)
                        break if ip == @host
                        break if node["nid"] == @nid
                        @node_pool.push(node) if @node_pool.size <= @node_poll_max
                    end
                end
            end
        end
    end


    class DHTServer < DHTClient
        def initialize(host, port, node_pool, node_poll_max)
            @host = host
            @port = port
            @node_pool = node_pool
            @node_poll_max = node_poll_max
            @udf = UDPSocket.new(Socket::AF_INET)
            @udf.bind(host, port)
            super()
        end

        public
        def start
            join_DHT
            listen
            re_join_DHT
            auto_send_find_node
        end

        protected
        def on_message(msg, address)
            begin
                if msg.fetch("y") == "r"
                    if msg.fetch("r").has_key?("nodes")
                        process_find_node_response(msg, address)
                    end
                elsif msg.fetch("y") == "q"
                    if msg.fetch("q") == "get_peers"
                        on_get_peers_request(msg, address)
                    elsif msg.fetch("q") == "announce_peer"
                        on_announce_peer_request(msg, address)
                    else
                        play_dead(msg, address)
                    end
                end
            rescue KeyError
            end
        end

        def on_get_peers_request(msg, address)
            infohash = msg["a"]["info_hash"]
            tid = msg["t"]
            nid = msg["a"]["id"]
            return unless (tid != nil &&  nid != nil)
            token = infohash[0...TOKEN_LENGTH]
            msg = {
                "t" => tid,
                "y" => "r",
                "r" => {
                    "id" => Utils::gen_nearest_nid(infohash, @nid),
                    "nodes" => "",
                    "token" => token,
                }
            }
            send_krpc(msg, address)
        end

        def on_announce_peer_request(msg, address)
            begin
                a = msg.fetch("a")
                infohash = a.fetch("info_hash")
                token = a.fetch("token")
                nid = a.fetch("id")
                tid = msg.fetch("t")

                if infohash[0...TOKEN_LENGTH] == token
                    if a.has_key?("implied_port") && a["implied_port"] != 0
                        port = address[1]
                    else
                        port = a.fetch("port")
                    end
                    return unless port.between?(1, 65535)
                    puts "magnet:?xt=urn:btih:#{Digest::hexencode(infohash)}, address:#{address[0]}:#{port}"
                end
            rescue KeyError
            ensure
                notify(msg, address)
            end
        end

        def play_dead(msg, address)
            return unless msg.has_key?("t")
            tid = msg["t"]
            msg = {
                "t" => tid,
                "y" => "e",
                "e" => [202, "Server Error"]
            }
            send_krpc(msg, address)
        end

        def notify(msg, address)
            tid = msg["t"]
            nid = msg["a"]["id"]
            msg = {
                "t" => tid,
                "y" => "r",
                "r" => {
                    "id" => Utils::gen_nearest_nid(nid, @nid)
                }
            }
            send_krpc(msg, address)
        end

        def listen
            Thread.new do
                loop do
                    begin
                        (msg, (_, port, ip)) = @udf.recvfrom(maxlen=65536)
                        on_message(msg.bdecode, [ip, port])
                    rescue StandardError
                    end
                end
            end
        end
    end
end


class Reactor
    def initialize(host, port, node_poll_max=500)
        @host = host
        @port = port
        @node_poll_max = node_poll_max
        @node_pool = []
        @node_pool.extend(MonitorMixin)     
    end

    public
    def start
        Thread.new do
            Crawler::DHTServer.new(@host, @port, @node_pool, @node_poll_max).start
        end
        loop { sleep(1) }
    end
end

begin
    Reactor.new("0.0.0.0", 6882, 500).start
rescue StandardError
end