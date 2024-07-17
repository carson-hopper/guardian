#include "gdpch.h"

#include "Guardian/Network/Packet/IpPacket.h"

#include <arpa/inet.h>
#include <netinet/ip.h>

IpPacket::IpPacket(Buffer packet)
    : m_Data(&packet) {

    auto *ip_hdr = m_Data->As<const struct ip>();
    m_IpHeader = ip_hdr;

    m_SourceIp = ip_hdr->ip_src.s_addr;
    m_DestinationIp = ip_hdr->ip_dst.s_addr;
    m_Protocol = ip_hdr->ip_p;
}

std::string IpPacket::GetSourceIpStr() const {
    char buffer[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &m_SourceIp, buffer, INET_ADDRSTRLEN);
    return buffer;
}

std::string IpPacket::GetDestinationIpStr() const {
    char buffer[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &m_DestinationIp, buffer, INET_ADDRSTRLEN);
    return buffer;
}

