#include "gdpch.h"
#include "Network/Detection/Detection.h"

Detection::Detection(const short protocol)
    : m_Protocol(protocol) {
}

std::tuple<int, unsigned char*, int> Detection::OnUpdate(IpPacket* ipPacket) {
    if (m_Protocol == IPPROTO_ICMP) {
        return OnIcmpUpdate(new IcmpPacket(ipPacket));
    }

    if (m_Protocol == IPPROTO_TCP) {
        return OnTcpUpdate(new TcpPacket(ipPacket));
    }

    return {NF_ACCEPT, nullptr, 0};
}