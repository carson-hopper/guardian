#pragma once

#include "Guardian/Network/Packet/IpPacket.h"
#include "Network/Detection/Detection.h"

#include <unordered_set>
#include <unordered_map>

#define SYN_FLOOD_THRESHOLD 1000
#define CLEANUP_INTERVAL 15

class SynFlood: public Detection {
public:
    SynFlood(short protocol): Detection(protocol) {}

    bool OnUpdate(const std::shared_ptr<IpPacket>& ipPacket, unsigned char** patcket, int length) override;

private:
    void cleanup_old_entries();

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