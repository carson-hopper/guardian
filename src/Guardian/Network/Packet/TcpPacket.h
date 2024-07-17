#pragma once

#include "Guardian/Core/Base.h"
#include "Guardian/Network/Packet/IpPacket.h"
#include "Guardian/Network/TcpConnection.h"

#include <optional>
#include <unordered_map>

class TcpPacket: public IpPacket {
public:
    TcpPacket(IpPacket* ipPacket); // NOLINT(*-explicit-constructor)

    [[nodiscard]] bool IsSyn() const { return (m_Flags & 0x02) != 0; }
    [[nodiscard]] bool IsAck() const { return (m_Flags & 0x10) != 0; }
    [[nodiscard]] bool IsRst() const { return (m_Flags & 0x04) != 0; }
    [[nodiscard]] bool IsFin() const { return (m_Flags & 0x01) != 0; }

    [[nodiscard]] uint16_t GetSourcePort() const { return m_SourcePort; }
    [[nodiscard]] uint16_t GetDestinationPort() const { return m_DestinationPort; }
    [[nodiscard]] uint8_t GetFlags() const { return m_Flags; }
    [[nodiscard]] uint64_t GetConnectionId() const;

    [[nodiscard]] std::shared_ptr<TcpConnection> GetConnection() const;

private:

private:
    uint16_t m_SourcePort;
    uint16_t m_DestinationPort;
    uint8_t m_Flags;

    static std::unordered_map<uint64_t, TcpConnection> s_Connections;
};