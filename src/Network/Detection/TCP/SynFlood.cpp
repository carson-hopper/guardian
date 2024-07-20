#include "gdpch.h"
#include "Network/Detection/TCP/SynFlood.h"
#include <netinet/tcp.h>

std::tuple<PacketAction, Buffer&> SynFlood::OnUpdate(const Ref<Packet>& packet) {
    Buffer& buffer = packet->GetBuffer();
    auto *tcp = packet->GetIpPacket()->GetProtocolHeader<const struct tcphdr>();

    m_FloodMap[std::format("{}:{}", packet->GetIpPacket()->GetSourceIp(), ntohs(tcp->dest))]++;

    const float time = Time::GetTime();
    if (const Timestep timestep = time - m_LastCheckTime; timestep.GetSeconds() > 1) {
        for (auto it = m_FloodMap.begin(); it != m_FloodMap.end();) {
            if (it->second >= 100) { // Threshold for SYN flood
                it = m_FloodMap.erase(it);
                GD_WARN("SYN Flood Detected: {}:{} -> {}:{}", packet->GetIpPacket()->GetSourceIpStr(), ntohs(tcp->source), packet->GetIpPacket()->GetDestinationIpStr(), ntohs(tcp->dest));
                return {DROP, buffer};
            } else {
                ++it;
            }
        }
        m_LastCheckTime = time;
    }

    return {ACCEPT, buffer};
}