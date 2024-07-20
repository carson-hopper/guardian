#include "gdpch.h"

#include "Guardian/Network/Packet/IpPacket.h"

#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

IpPacket::IpPacket(const Buffer& buffer)
    : m_Data(buffer) {

    m_IpHeader = m_Data.As<iphdr>();

    auto* ip = m_Data.As<struct iphdr>();
    m_SourceIp = ip->saddr;
    m_DestinationIp = ip->daddr;
    m_Protocol = static_cast<Protocol>(ip->protocol);

    if (m_Protocol == ICMP) {
        // m_IcmpPacket = CreateRef<IcmpPacket>(this);
    } else if (m_Protocol == TCP) {
        // m_TcpPacket = CreateRef<TcpPacket>(this);
    } else if (m_Protocol == UDP) {

    }
}

std::string IpPacket::GetSourceIpStr() const {
    return inet_ntoa(*reinterpret_cast<const in_addr*>(&m_SourceIp));
}

std::string IpPacket::GetDestinationIpStr() const {
    return inet_ntoa(*reinterpret_cast<const in_addr*>(&m_DestinationIp));
}

std::string IpPacket::GetProtocolName() const {
    switch (GetProtocol()) {
        case IPPROTO_ICMP:
            return "ICMP";
        case IPPROTO_TCP:
            return "TCP";
        case IPPROTO_UDP:
            return "UDP";
        case IPPROTO_GRE:
            return "GRE";
        default:
            return std::string(std::format("{}", (int8_t)GetProtocol()));
    }
}

uint16_t IpPacket::CalculateIpChecksum() const {
    auto* ip = reinterpret_cast<iphdr*>(m_Data.Data);

    const uint16_t oldChecksum = ip->check;
    ip->check = 0;

    register unsigned long sum = 0;
    const auto* addr = reinterpret_cast<unsigned short *>(ip);

    unsigned int count = ip->ihl << 2;
    for (; count > 1; count -= 2) {
        sum += * addr++;
    }

    if(count > 0)
        sum += ((*addr)&htons(0xFF00));

    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);
    sum = ~sum;

    ip->check = oldChecksum;
    return ((unsigned short)sum);
}

uint16_t IpPacket::CalculateTcpChecksum() {
    auto* ip = reinterpret_cast<iphdr*>(m_Data.Data);
    auto *tcp = GetProtocolHeader<tcphdr>();

    uint16_t oldChecksum = tcp->check;



    tcp->check = oldChecksum;

    return 0;
}

uint16_t IpPacket::CalculateUdpChecksum(udphdr* udp, int length) {
    auto* ip = reinterpret_cast<iphdr*>(m_Data.Data);
    uint8_t* buffer = m_Data.Data;

    const uint16_t oldChecksum = udp->check;

    register unsigned long sum = 0;
    unsigned short udpLen = htons(udp->len);
    //printf("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~udp len=%dn", udpLen);
    //add the pseudo header
    //printf("add pseudo headern");
    //the source ip
    sum += (ip->saddr>>16)&0xFFFF;
    sum += (ip->saddr)&0xFFFF;
    //the dest ip
    sum += (ip->daddr>>16)&0xFFFF;
    sum += (ip->daddr)&0xFFFF;
    //protocol and reserved: 17
    sum += htons(IPPROTO_UDP);
    //the length
    sum += udp->len;

    //add the IP payload
    //printf("add ip payloadn");
    //initialize checksum to 0
    udp->check = 0;
    while (udpLen > 1) {
        sum += * buffer++;
        udpLen -= 2;
    }
    //if any bytes left, pad the bytes and add
    if(udpLen > 0) {
        //printf("+++++++++++++++padding: %dn", udpLen);
        sum += ((*buffer)&htons(0xFF00));
    }
    //Fold sum to 16 bits: add carrier to result
    //printf("add carriern");
    while (sum>>16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    //printf("one's complementn");
    sum = ~sum;

    udp->check = oldChecksum;
    return ((unsigned short)sum == 0x0000)?0xFFFF:(unsigned short)sum;
}
