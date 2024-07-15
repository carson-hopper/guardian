#include "gdpch.h"

#include "Guardian/Network/Packet/TcpPacket.h"

#include <netinet/ip.h>
#include <netinet/tcp.h>

std::unordered_map<uint64_t, TcpConnection> TcpPacket::s_Connections;

TcpPacket::TcpPacket(const std::shared_ptr<IpPacket>& ipPacket)
    : IpPacket(*ipPacket), m_SourcePort(0), m_DestinationPort(0), m_Flags(0) {

    if (ipPacket->GetProtocol() == IPPROTO_TCP) {
        auto *header = ipPacket->GetProtocolHeader<const struct tcphdr>();

        m_SourcePort = ntohs(header->source);
        m_DestinationPort = ntohs(header->dest);
        m_Flags = header->th_flags;
    }
}

uint64_t TcpPacket::GetConnectionId() const {
    return (static_cast<uint64_t>(GetSourceIp()) << 32) | GetDestinationIp();
}

void TcpPacket::SetConnectionState()  {
    const uint64_t connectionId = GetConnectionId();
    s_Connections[connectionId].SetState(m_Flags);
}

std::optional<TcpConnection> TcpPacket::GetConnection() const {
    const uint64_t connectionId = GetConnectionId();
    auto it = s_Connections.find(connectionId);
    if (it != s_Connections.end()) {
        return it->second;
    }
    return std::optional<TcpConnection>{};
}
