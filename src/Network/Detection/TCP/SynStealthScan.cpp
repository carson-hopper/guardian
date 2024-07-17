#include "gdpch.h"
#include "Network/Detection/TCP/SynStealthScan.h"

#include "Guardian/Guardian.h"
#include "Guardian/Network/Packet/TcpPacket.h"
#include "Guardian/Network/TcpConnection.h"


std::tuple<int, unsigned char*, int> SynStealthScan::OnTcpUpdate(TcpPacket* tcpPacket) {
    GD_PROFILE_SCOPE("SynStealthScan");

    if (const auto connection = tcpPacket->GetConnection()) {
        const uint32_t src_ip = tcpPacket->GetSourceIp();

        auto& counter = m_SynMap[src_ip];
        counter.last_seen = Time::GetTime();

        if (connection->GetState() == SYN_SENT) {
            counter.syn_count++;
        } else if (connection->GetState() == ESTABLISHED) {
            counter.ack_count++;
        } else if (connection->GetState() == RESET) {
            counter.rst_count++;
        }

        if (counter.syn_count > 10 &&
            counter.ack_count < counter.syn_count / 2 &&
            counter.rst_count < counter.syn_count / 2) {
            // std::cout << "Potential half-open SYN scan detected from IP: " << ipPacket->GetSourceIpStr() << std::endl;
            // return {NF_DROP, tcpPacket->GetData()->Data, tcpPacket->GetData()->Size};
        }
    }

    float currentTime = Time::GetTime();
    for (auto it = m_SynMap.begin(); it != m_SynMap.end(); ) {
        Timestep timestep = currentTime - it->second.last_seen;
        if (timestep.GetSeconds() > 60) {
            it = m_SynMap.erase(it);
        } else {
            ++it;
        }
    }

    return {NF_ACCEPT, tcpPacket->GetData()->Data, tcpPacket->GetData()->Size};
}