#pragma once

#include "Guardian/Network/Packet/IpPacket.h"
#include "Network/Detection/Detection.h"

#include <unordered_set>
#include <unordered_map>

struct icmp_counter {
    uint32_t count;
    float last_seen;
    std::unordered_set<uint32_t> destinations;
};

class IcmpScan: public Detection {
public:

    IcmpScan(const short protocol): Detection(protocol) {}

    bool OnUpdate(const std::shared_ptr<IpPacket>& ipPacket, unsigned char** patcket, int length) override;

private:

    void cleanup_old_entries();

    std::unordered_map<uint32_t, icmp_counter> m_IcmpMap;

};