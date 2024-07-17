#pragma once

#include "Guardian/Core/Buffer.h"
#include <netinet/ip.h>

class IpPacket {
public:
    IpPacket(Buffer packet);
    ~IpPacket() = default;

    [[nodiscard]] const ip* IpHeader() const { return m_IpHeader; }
    [[nodiscard]] uint8_t GetProtocol() const { return m_Protocol; }
    [[nodiscard]] Buffer* GetData() const { return m_Data; }
    [[nodiscard]] uint32_t GetSourceIp() const { return m_SourceIp; }
    [[nodiscard]] uint32_t GetDestinationIp() const { return m_DestinationIp; }
    [[nodiscard]] std::string GetSourceIpStr() const;
    [[nodiscard]] std::string GetDestinationIpStr() const;

    template<typename T>
    T* GetProtocolHeader() {
        return (T*)(m_IpHeader + (m_IpHeader->ip_hl * 4));
        // return reinterpret_cast<const T>(reinterpret_cast<const unsigned char*>(m_IpHeader) + (m_IpHeader->ip_hl * 4));
    }

private:
    const ip* m_IpHeader;
    Buffer* m_Data;

    uint8_t m_Protocol;
    uint32_t m_SourceIp;
    uint32_t m_DestinationIp;
};