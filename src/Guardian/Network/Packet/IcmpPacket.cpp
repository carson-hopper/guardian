#include "gdpch.h"
#include "Guardian/Network/Packet/IcmpPacket.h"

#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

IcmpPacket::IcmpPacket(const std::shared_ptr<IpPacket>& ipPacket)
    : IpPacket(*ipPacket), m_Type(0), m_Code(0), m_Checksum(0) {

    if (ipPacket->GetProtocol() == IPPROTO_ICMP) {
        auto *header = ipPacket->GetProtocolHeader<const struct icmp>();

        m_Type = header->icmp_type;
        m_Code = header->icmp_code;
        m_Checksum = header->icmp_cksum;
    }
}