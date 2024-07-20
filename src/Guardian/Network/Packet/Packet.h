#pragma once

#include "Guardian/Core/Buffer.h"
#include "Guardian/Network/Packet/IpPacket.h"
#include "Guardian/Network/Packet/PacketAction.h"
#include "Guardian/Network/TcpConnection.h"

#include <libnetfilter_queue/libnetfilter_queue.h>

#include <map>

class Packet {
public:
    Packet(nfq_q_handle* queueHandle, nfq_data* packetHandle, nfqnl_msg_packet_hdr* packetMessageHandle);
    ~Packet() = default;

    [[nodiscard]] virtual uint32_t& GetId() { return m_Id; }
    [[nodiscard]] virtual nfq_q_handle* GetQueueHandle() const { return m_QueueHandle; }
    [[nodiscard]] virtual nfq_data* GetPacketHandle() const { return m_PacketHandle; }
    [[nodiscard]] virtual nfqnl_msg_packet_hdr* GetPacketMessageHandle() const { return m_PacketMessageHandle; }

    [[nodiscard]] virtual Buffer& GetBuffer() { return m_Payload; }
    [[nodiscard]] virtual Ref<IpPacket> GetIpPacket() { return m_IpPacket; }

    [[nodiscard]] uint64_t GetTcpConnectionId();
    [[nodiscard]] Ref<TcpConnection> GetTcpConnection();

    int32_t SetVerdict(PacketAction verdict);

private:
    uint32_t m_Id;
    nfq_q_handle* m_QueueHandle;
    nfq_data* m_PacketHandle;
    nfqnl_msg_packet_hdr* m_PacketMessageHandle;

    Buffer m_Payload;
    Ref<IpPacket> m_IpPacket;

    int32_t m_Verdict;
    bool m_HasSetVerdict;

    static std::map<uint64_t, TcpConnection> s_Connections;
};
