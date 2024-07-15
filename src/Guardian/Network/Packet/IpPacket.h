#pragma once

#include "Guardian/Core/Base.h"

class IpPacket {
public:
    IpPacket(const unsigned char *packet, int length);
    ~IpPacket() = default;

    [[nodiscard]] const struct ip* IpHeader() const { return m_IpHeader; }
    [[nodiscard]] uint8_t GetProtocol() const { return m_Protocol; }
    [[nodiscard]] const uint8_t* GetData() const { return m_Data; }
    [[nodiscard]] uint32_t GetSourceIp() const { return m_SourceIp; }
    [[nodiscard]] uint32_t GetDestinationIp() const { return m_DestinationIp; }
    [[nodiscard]] std::string GetSourceIpStr() const;
    [[nodiscard]] std::string GetDestinationIpStr() const;

    template<typename T>
    T* GetProtocolHeader() {
        return reinterpret_cast<const T*>(reinterpret_cast<const unsigned char*>(m_IpHeader) + (m_IpHeader->ip_hl * 4));
    }

private:
    const ip* m_IpHeader;
    const unsigned char* m_Data;
    size_t m_Length;

    uint8_t m_Protocol;
    uint32_t m_SourceIp;
    uint32_t m_DestinationIp;
};