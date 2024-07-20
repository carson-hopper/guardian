#pragma once

#include "Guardian/Core/Buffer.h"
#include "Guardian/Network/Protocol.h"

#include <netinet/ip.h>
#include <netinet/udp.h>

class IpPacket {
public:
    IpPacket(const Buffer& buffer);
    ~IpPacket() = default;

    [[nodiscard]] iphdr* GetIpHeader() const { return m_IpHeader; }
    [[nodiscard]] Protocol GetProtocol() const { return m_Protocol; }
    [[nodiscard]] std::string GetProtocolName() const;
    [[nodiscard]] Buffer& GetData() { return m_Data; }
    [[nodiscard]] uint32_t GetSourceIp() const { return m_SourceIp; }
    [[nodiscard]] uint32_t GetDestinationIp() const { return m_DestinationIp; }
    [[nodiscard]] std::string GetSourceIpStr() const;
    [[nodiscard]] std::string GetDestinationIpStr() const;

    [[nodiscard]] uint16_t CalculateIpChecksum() const;
    uint16_t CalculateTcpChecksum();
    uint16_t CalculateUdpChecksum(udphdr* udp, int length);

    // virtual Ref<UdpPacket> GetUdpPacket() { return m_UdpPacket; }

    template<typename T>
    T* GetProtocolHeader() {
        return reinterpret_cast<T*>(m_IpHeader + (m_IpHeader->ihl * 4));
        // return reinterpret_cast<const T>(reinterpret_cast<const unsigned char*>(m_IpHeader) + (m_IpHeader->ip_hl * 4));
    }

private:
    iphdr* m_IpHeader = nullptr;
    Buffer m_Data;

    Protocol m_Protocol = PROTOCOL_UNKNOWN;
    uint32_t m_SourceIp = 0;
    uint32_t m_DestinationIp = 0;
};