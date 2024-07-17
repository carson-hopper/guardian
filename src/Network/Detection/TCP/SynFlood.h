#pragma once

#include "Guardian/Network/Packet/IpPacket.h"
#include "Network/Detection/Detection.h"

#include <unordered_set>
#include <unordered_map>

class SynFlood: public Detection {
public:
    SynFlood(const short protocol): Detection(protocol) {}

    std::tuple<int, unsigned char*, int> OnTcpUpdate(TcpPacket* tcpPacket) override;

private:
    struct syn_counter {
        uint32_t syn_count;
        uint32_t ack_count;
        uint32_t rst_count;
        float last_seen;
        std::unordered_set<uint16_t> ports;
    };

    std::unordered_map<uint32_t, syn_counter> m_SynMap;
};