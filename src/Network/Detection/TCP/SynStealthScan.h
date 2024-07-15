#pragma once

#include "Guardian/Network/Packet/IpPacket.h"
#include "Network/Detection/Detection.h"

#include <unordered_set>
#include <unordered_map>

#define THRESHOLD 10
#define CLEANUP_INTERVAL 60

class SynStealthScan: public Detection {
public:
    SynStealthScan(short protocol): Detection(protocol) {}

    bool OnUpdate(const std::shared_ptr<IpPacket>& ipPacket, unsigned char** patcket, int length) override;

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