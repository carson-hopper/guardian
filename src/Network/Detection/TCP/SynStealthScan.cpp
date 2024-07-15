#include "gdpch.h"
#include "Network/Detection/TCP/SynStealthScan.h"

#include "Guardian/Guardian.h"
#include "Guardian/Network/Packet/TcpPacket.h"
#include "Guardian/Network/TcpConnection.h"

bool SynStealthScan::OnUpdate(const std::shared_ptr<IpPacket>& ipPacket, unsigned char** patcket, int length) {
    if (const auto tcpPacket = std::make_shared<TcpPacket>(ipPacket)) {

        const auto connection = tcpPacket->GetConnection();
        if (!connection.has_value()) return true;

        const uint32_t src_ip = ipPacket->GetSourceIp();
        const uint16_t dst_port = tcpPacket->GetDestinationPort();

        auto& counter = m_SynMap[src_ip];
        counter.last_seen = Time::GetTime();

        if (connection->GetState() == TcpConnectionState::SYN_SENT) {
            counter.syn_count++;
        } else if (connection->GetState() == TcpConnectionState::ESTABLISHED) {
            counter.ack_count++;
        } else if (connection->GetState() == TcpConnectionState::RESET) {
            counter.rst_count++;
        }

        if (counter.syn_count > THRESHOLD &&
            counter.ack_count < counter.syn_count / 2 &&
            counter.rst_count < counter.syn_count / 2) {
            // std::cout << "Potential half-open SYN scan detected from IP: " << ipPacket->GetSourceIpStr() << std::endl;
            return true; // Indicate that the packet should be dropped
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