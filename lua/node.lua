local dht = require 'dht'
local socket = require 'socket'

local sock = socket.udp()
sock:setsockname('*', 6881)
local node = dht.node_create(nil, function(data, ip, port)
    sock:sendto(data, ip, port)
end)
node:set_bootstrap_callback(function(ready)
    node:get_peers('4E64AAAF48D922DBD93F8B9E4ACAA78C99BC1F40', function(infohash, peers)
        print(string.format('Search for %s done. Peers:', infohash))
        if peers then
            for _, v in ipairs(peers) do
                print(v[1], v[2])
            end
        end
    end)
end)

node:start()

while true do
    local timeout = node:timeout()
    local t = socket.select({sock}, nil, timeout)
    if t[sock] then
        local data, ip, port = sock:receivefrom()
        node:input(data, ip, port)
    end
    node:work()
end
