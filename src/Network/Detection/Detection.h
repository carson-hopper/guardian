#pragma once

#include "Guardian/Network/Packet/IpPacket.h"
#include "Guardian/Network/Packet/TcpPacket.h"
#include "Guardian/Network/Packet/IcmpPacket.h"

#include <tuple>
#include <linux/netfilter.h>

class Detection {
public:
    Detection(short protocol);
    virtual ~Detection() = default;

    virtual bool OnAttach() { return true; }
    virtual bool OnDetach() { return true; }

    std::tuple<int, unsigned char*, int> OnUpdate(IpPacket* ipPacket);
    virtual std::tuple<int, unsigned char*, int> OnTcpUpdate(TcpPacket* tcpPacket) { return {NF_ACCEPT, nullptr, 0}; }
    virtual std::tuple<int, unsigned char*, int> OnIcmpUpdate(IcmpPacket* icmpPacket) { return {NF_ACCEPT, nullptr, 0}; }

    [[nodiscard]] const short &GetProtocol() const { return m_Protocol; }

protected:
    short m_Protocol = 0;
};