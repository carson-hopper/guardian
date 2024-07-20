#include "gdpch.h"
#include "Layer/NfqLayer.h"

#include "Guardian/Network/Packet/Packet.h"
#include "Guardian/Network/Packet/IpPacket.h"

#include "Network/Detection/ICMP/IcmpFlood.h"
#include "Network/Detection/UDP/DnsBlock.h"

#include <libnetfilter_queue/libnetfilter_queue.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>

// std::ofstream logfile("traffic_data.csv", std::ios_base::app);
int NfqLayer::PacketCallback(nfq_q_handle *queueHandle, nfgenmsg *packetMessage, nfq_data *packetHandle, void *data) {
    GD_PROFILE_FUNCTION();

    nfqnl_msg_packet_hdr* packetMessageHandle = nfq_get_msg_packet_hdr(packetHandle);
    if (!packetMessageHandle)
        return nfq_set_verdict(queueHandle, 0, ACCEPT, 0, nullptr);

    const Ref<Packet> packet = CreateRef<Packet>(queueHandle, packetHandle, packetMessageHandle);

    uint8_t* buffer = packet->GetBuffer().Data;
    auto* ip_header = reinterpret_cast<iphdr*>(buffer);
    // GD_INFO("Checksum: {:x} -> {:x}", ip_header->check, packet->GetIpPacket()->CalculateIpChecksum());

    ip_header->check = packet->GetIpPacket()->CalculateIpChecksum();

    // logfile << packet->GetIpPacket()->GetProtocolName() << "," << packet->GetIpPacket()->GetSourceIpStr() << "," << packet->GetIpPacket()->GetDestinationIpStr() << "," << packet->GetBuffer().Size << std::endl;

    if (const auto layer = static_cast<NfqLayer*>(data)) {
        for (const auto& mitigation : layer->m_Mitigations) {
            if (mitigation->GetProtocol() != packet->GetIpPacket()->GetProtocol()) continue;

            const auto [verdict, buffer] = mitigation->OnUpdate(packet);

            if (verdict == DROP || memcmp(packet->GetBuffer().Data, buffer.Data, glm::min(packet->GetBuffer().Size, buffer.Size)) != 0)
                return packet->SetVerdict(verdict);
        }
    }

    return packet->SetVerdict(ACCEPT);
}

bool NfqLayer::OnAttach() {
    GD_ASSERT(PushMitigation<DnsBlock>(), "Failed to load DnsBlock");
    // PushMitigation<IcmpFlood>();
    // PushMitigation<SynFlood>();

    m_Handle = nfq_open();
    if (!m_Handle) {
        GD_ERROR("Error during nfq_open(): %i", strerror(errno));
        return false;
    }

    if (nfq_unbind_pf(m_Handle, AF_INET) < 0) {
        GD_ERROR("Error during nfq_unbind_pf(): %i", strerror(errno));
        nfq_close(m_Handle);
        return false;
    }

    if (nfq_bind_pf(m_Handle, AF_INET) < 0) {
        GD_ERROR("Error during nfq_bind_pf(): %i", strerror(errno));
        nfq_close(m_Handle);
        return false;
    }

    constexpr int queueNumber = 0;
    m_QueueHandle = nfq_create_queue(m_Handle, queueNumber, &PacketCallback, this);
    nfq_set_mode(m_QueueHandle, NFQNL_COPY_PACKET, 0xffff);

    if (!m_QueueHandle) {
        GD_ERROR("Error during nfq_create_queue(): %i", strerror(errno));
        nfq_close(m_Handle);
        return false;
    }

    if (nfq_set_mode(m_QueueHandle, NFQNL_COPY_PACKET, 0x5EE) < 0) {
        GD_ERROR("Can't set packet_copy mode: %i", strerror(errno));
        nfq_destroy_queue(m_QueueHandle);
        nfq_close(m_Handle);
        return false;
    }

    m_fd = nfq_fd(m_Handle);
    if (m_fd < 0) {
        GD_ERROR("Failed to get file descriptor for NFQUEUE: %i", strerror(errno));
        nfq_destroy_queue(m_QueueHandle);
        nfq_close(m_Handle);
        return false;
    }

    GD_INFO("libnetfilter attacked");

    return true;
}

bool NfqLayer::OnDetach() {
    // logfile.close();

    for (const auto& mitigation : m_Mitigations)
        mitigation->OnDetach();

    if (m_QueueHandle)
        nfq_destroy_queue(m_QueueHandle);

    if (m_Handle)
        nfq_close(m_Handle);

    return true;
}

void NfqLayer::OnUpdate(Guardian::Timestep ts) {
    char buffer[0x1000] __attribute__((aligned));
    if (const int rv = static_cast<const int>(recv(m_fd, buffer, sizeof(buffer), 0)); rv >= 0)
        nfq_handle_packet(m_Handle, buffer, rv);
}