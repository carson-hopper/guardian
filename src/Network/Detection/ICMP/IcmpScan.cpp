#include "gdpch.h"

#include "Network/Detection/ICMP/IcmpScan.h"

#include "Guardian/Guardian.h"
#include "Guardian/Network/Packet/IcmpPacket.h"

#include <netinet/ip_icmp.h>

std::tuple<int, unsigned char*, int> IcmpScan::OnIcmpUpdate(IcmpPacket* icmpPacket)  {
    GD_PROFILE_SCOPE("IcmpScan");

    if (icmpPacket->GetSourceIpStr().contains("216.66.10.42"))
        return {NF_ACCEPT, icmpPacket->GetData()->Data, icmpPacket->GetData()->Size};

    const uint32_t src_ip = icmpPacket->GetSourceIp();
    const uint32_t dst_ip = icmpPacket->GetDestinationIp();

    if (icmpPacket->GetType() == ICMP_ECHO) { // Echo request
        auto& counter = m_IcmpMap[src_ip];
        counter.count++;
        if (!counter.destinations.contains(dst_ip))
            counter.destinations.insert(dst_ip);
        counter.last_seen = Time::GetTime();

        if (counter.destinations.size() > 1 &&
            counter.count > 5) {
            // std::cout << std::format("Potential ICMP scan detected | {} - {} | {} -> {}", counter.destinations.size(), counter.count, ipPacket->GetSourceIpStr(), ipPacket->GetDestinationIpStr()) << std::endl;
            // m_IcmpMap.erase(src_ip);
            return {NF_DROP, icmpPacket->GetData()->Data, icmpPacket->GetData()->Size};
        }
    }

    const float currentTime = Time::GetTime();

    for (auto it = m_IcmpMap.begin(); it != m_IcmpMap.end(); ) {
        const Timestep timestep = currentTime - it->second.last_seen;
        if (timestep.GetSeconds() > 20) {
            it = m_IcmpMap.erase(it);
        } else {
            ++it;
        }
    }

    return {NF_ACCEPT, icmpPacket->GetData()->Data, icmpPacket->GetData()->Size};
}