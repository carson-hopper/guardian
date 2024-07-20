#include "gdpch.h"
#include "Network/Detection/ICMP/IcmpFlood.h"

std::tuple<PacketAction, Buffer&> IcmpFlood::OnUpdate(const Ref<Packet>& packet) {
    Buffer& buffer = packet->GetBuffer();

    if (packet->GetIpPacket()->GetSourceIpStr().contains("216.66.10.42"))
        return {ACCEPT, buffer};

    m_FloodMap[packet->GetIpPacket()->GetSourceIp()]++;

    const float time = Time::GetTime();
    if (const Timestep timestep = time - m_LastCheckTime; timestep.GetSeconds() > 1) {
        for (auto it = m_FloodMap.begin(); it != m_FloodMap.end();) {
            if (it->second >= 25) { // Threshold for ICMP flood
                it = m_FloodMap.erase(it);
                GD_WARN("ICMP Flood Detected: {} -> {}", packet->GetIpPacket()->GetSourceIpStr().c_str(), packet->GetIpPacket()->GetDestinationIpStr().c_str());
                return {DROP, buffer};
            } else {
                ++it;
            }
        }
        m_LastCheckTime = time;
    }

    return {ACCEPT, buffer};
}