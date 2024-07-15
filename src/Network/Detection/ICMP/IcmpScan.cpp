#include "gdpch.h"

#include "Network/Detection/ICMP/IcmpScan.h"

#include "Guardian/Guardian.h"
#include "Guardian/Network/Packet/IcmpPacket.h"

#include <netinet/ip_icmp.h>

bool IcmpScan::OnUpdate(const std::shared_ptr<IpPacket>& ipPacket, unsigned char** patcket, int length) {
    if (const auto icmpPacket = std::make_shared<IcmpPacket>(ipPacket)) {
        const uint32_t src_ip = ipPacket->GetSourceIp();
        const uint32_t dst_ip = ipPacket->GetDestinationIp();

        if (ipPacket->GetSourceIpStr().contains("216.66.10.42"))
            return true;

        if (icmpPacket->GetType() == ICMP_ECHO) { // Echo request
            auto& counter = m_IcmpMap[src_ip];
            counter.count++;
            if (!counter.destinations.contains(dst_ip))
                counter.destinations.insert(dst_ip);
            counter.last_seen = Time::GetTime();

            if (counter.destinations.size() > 1 && counter.count > SCAN_THRESHOLD) {
                // std::cout << std::format("Potential ICMP scan detected | {} - {} | {} -> {}", counter.destinations.size(), counter.count, ipPacket->GetSourceIpStr(), ipPacket->GetDestinationIpStr()) << std::endl;
                // m_IcmpMap.erase(src_ip);
                return false;
            }
        }
    }

    cleanup_old_entries();
    return true;
}

void IcmpScan::cleanup_old_entries() {
    const float currentTime = Time::GetTime();

    for (auto it = m_IcmpMap.begin(); it != m_IcmpMap.end(); ) {
        const Timestep timestep = currentTime - it->second.last_seen;
        if (timestep.GetSeconds() > CLEANUP_INTERVAL) {
            it = m_IcmpMap.erase(it);
        } else {
            ++it;
        }
    }
}