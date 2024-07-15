#include "gdpch.h"
#include "Network/Detection/TCP/SynFlood.h"

#include "Guardian/Guardian.h"
#include "Guardian/Network/Packet/TcpPacket.h"

bool SynFlood::OnUpdate(const std::shared_ptr<IpPacket>& ipPacket, unsigned char** patcket, int length) {
    if (const auto tcpPacket = std::make_shared<TcpPacket>(ipPacket)) {
        const auto connection = tcpPacket->GetConnection();
        if (!connection.has_value()) return true;

        uint32_t src_ip = ipPacket->GetSourceIp();
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

        // If the number of SYN packets without a corresponding ACK is greater than the threshold, consider it a SYN flood
        if (counter.syn_count > SYN_FLOOD_THRESHOLD
            && counter.ports.size() >= 2
            && counter.ack_count < counter.syn_count / 2) {
            // std::cout << std::format("Potential SYN flood | {} -> {}", ipPacket->GetSourceIpStr(), ipPacket->GetDestinationIpStr()) << std::endl;
            return true;
        }
    }

    float currentTime = Time::GetTime();
    for (auto it = m_SynMap.begin(); it != m_SynMap.end(); ) {
        Timestep timestep = currentTime - it->second.last_seen;
        if (timestep.GetSeconds() > CLEANUP_INTERVAL) {
            it = m_SynMap.erase(it);
        } else {
            ++it;
        }
    }

    return true;
}

void SynFlood::cleanup_old_entries() {
    float currentTime = Time::GetTime();
    for (auto it = m_SynMap.begin(); it != m_SynMap.end(); ) {
        Timestep timestep = currentTime - it->second.last_seen;
        if (timestep.GetSeconds() > CLEANUP_INTERVAL) {
            it = m_SynMap.erase(it);
        } else {
            ++it;
        }
    }
}