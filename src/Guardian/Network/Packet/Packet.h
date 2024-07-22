#pragma once

#include "Guardian/Core/Buffer.h"
#include "Guardian/Network/Packet/IpPacket.h"
#include "Guardian/Network/Packet/PacketAction.h"
#include "Guardian/Network/TcpConnection.h"

#include <libnetfilter_queue/libnetfilter_queue.h>

#include <map>

class Packet {
public:
    Packet(OptionalRefWrapper<nfq_q_handle> queueHandle, OptionalRefWrapper<nfq_data> packetHandle, OptionalRefWrapper<nfqnl_msg_packet_hdr> packetMessageHandle);
    ~Packet() = default;

    [[nodiscard]] virtual uint32_t& GetId() { return m_Id; }
    [[nodiscard]] virtual OptionalRefWrapper<nfq_q_handle> GetQueueHandle() const { return m_QueueHandle; }
    [[nodiscard]] virtual OptionalRefWrapper<nfq_data> GetPacketHandle() const { return m_PacketHandle; }
    [[nodiscard]] virtual OptionalRefWrapper<nfqnl_msg_packet_hdr> GetPacketMessageHandle() const { return m_PacketMessageHandle; }
    [[nodiscard]] virtual int32_t GetVerdict() { return m_Verdict; }

    [[nodiscard]] Buffer& GetBuffer();
    [[nodiscard]] Ref<IpPacket> GetIpPacket();

    [[nodiscard]] uint64_t GetTcpConnectionId();
    [[nodiscard]] Ref<TcpConnection> GetTcpConnection();

    int32_t SetVerdict(PacketAction verdict);

private:
    uint32_t m_Id;
    OptionalRefWrapper<nfq_q_handle> m_QueueHandle;
    OptionalRefWrapper<nfq_data> m_PacketHandle;
    OptionalRefWrapper<nfqnl_msg_packet_hdr> m_PacketMessageHandle;

    Buffer m_Payload;
    Ref<IpPacket> m_IpPacket;

    int32_t m_Verdict;
    bool m_HasSetVerdict;

    static std::map<uint64_t, TcpConnection> s_Connections;
};
