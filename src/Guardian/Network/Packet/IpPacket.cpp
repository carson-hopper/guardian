#include "gdpch.h"

#include "Guardian/Network/Packet/IpPacket.h"

#include <arpa/inet.h>
#include <netinet/ip.h>

IpPacket::IpPacket(const unsigned char *packet, int length)
    : m_Data(packet), m_Length(length) {

    auto *ip_hdr = reinterpret_cast<const struct ip*>(packet);
    m_IpHeader = ip_hdr;

    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip_hdr->ip_src), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_hdr->ip_dst), dst_ip, INET_ADDRSTRLEN);

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

