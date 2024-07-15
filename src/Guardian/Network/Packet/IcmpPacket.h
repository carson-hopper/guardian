#pragma once

#include "Guardian/Core/Base.h"
#include "Guardian/Network/Packet/IpPacket.h"

class IcmpPacket: public IpPacket {
public:
    IcmpPacket(const std::shared_ptr<IpPacket>& ipPacket);

    [[nodiscard]] uint8_t GetType() const { return m_Type; }
    [[nodiscard]] uint8_t GetCode() const { return m_Code; }
    [[nodiscard]] uint16_t GetChecksum() const { return m_Checksum; }

private:
    uint8_t m_Type;
    uint8_t m_Code;
    uint16_t m_Checksum;
};