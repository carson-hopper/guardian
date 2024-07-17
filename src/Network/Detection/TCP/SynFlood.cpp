#include "gdpch.h"
#include "Network/Detection/TCP/SynFlood.h"

#include "Guardian/Guardian.h"
#include "Guardian/Network/Packet/TcpPacket.h"

std::tuple<int, unsigned char*, int> SynFlood::OnTcpUpdate(TcpPacket* tcpPacket) {
    GD_PROFILE_SCOPE("SynFlood");

    if (const auto connection = tcpPacket->GetConnection()) {
        uint32_t src_ip = tcpPacket->GetSourceIp();
        uint16_t dst_port = tcpPacket->GetDestinationPort();

        auto& counter = m_SynMap[src_ip];
        counter.last_seen = Time::GetTime();

        if (connection->GetState() == TcpConnectionState::SYN_SENT) {
            counter.syn_count++;
            if (!counter.ports.contains(dst_port))
                counter.ports.insert(dst_port);
        } else if (connection->GetState() == TcpConnectionState::ESTABLISHED) {
            counter.ack_count++;
        } else if (connection->GetState() == TcpConnectionState::RESET) {
            counter.rst_count++;
        }

        if (counter.syn_count > 1000
            && counter.ports.size() >= 2
            && counter.ack_count < counter.syn_count / 2) {
            // std::cout << std::format("Potential SYN flood | {} -> {}", ipPacket->GetSourceIpStr(), ipPacket->GetDestinationIpStr()) << std::endl;
            // return {NF_DROP, tcpPacket->GetData()->Data, tcpPacket->GetData()->Size};
        }
    }

    float currentTime = Time::GetTime();
    for (auto it = m_SynMap.begin(); it != m_SynMap.end(); ) {
        Timestep timestep = currentTime - it->second.last_seen;
        if (timestep.GetSeconds() > 15) {
            it = m_SynMap.erase(it);
        } else {
            ++it;
        }
    }

    return {NF_ACCEPT, tcpPacket->GetData()->Data, tcpPacket->GetData()->Size};
}