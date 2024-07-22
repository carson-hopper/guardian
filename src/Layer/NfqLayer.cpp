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

    Packet packet(*queueHandle, *packetHandle, *packetMessageHandle);
    // logfile << packet.GetIpPacket()->GetProtocolName() << "," << packet.GetIpPacket()->GetSourceIpStr() << "," << packet.GetIpPacket()->GetDestinationIpStr() << "," << packet.GetBuffer().Size << std::endl;

    if (const auto layer = static_cast<NfqLayer*>(data)) {
        for (const auto& mitigation : layer->m_Mitigations) {
            if (mitigation->GetProtocol() != packet.GetIpPacket()->GetProtocol())
                continue;

            if (const PacketAction verdict = mitigation->OnUpdate(packet); verdict == DROP)
                return packet.SetVerdict(verdict);
        }
    }

    return packet.SetVerdict(ACCEPT);
}

bool NfqLayer::OnAttach() {

    m_Handle = *nfq_open();
    if (!m_Handle.has_value()) {
        GD_ERROR("Error during nfq_open(): %i", strerror(errno));
        return false;
    }

    if (nfq_unbind_pf(&m_Handle->get(), AF_INET) < 0) {
        GD_ERROR("Error during nfq_unbind_pf(): %i", strerror(errno));
        nfq_close(&m_Handle->get());
        return false;
    }

    if (nfq_bind_pf(&m_Handle->get(), AF_INET) < 0) {
        GD_ERROR("Error during nfq_bind_pf(): %i", strerror(errno));
        nfq_close(&m_Handle->get());
        return false;
    }

    constexpr int queueNumber = 0;
    m_QueueHandle = *nfq_create_queue(&m_Handle->get(), queueNumber, &PacketCallback, this);

    if (!m_QueueHandle.has_value()) {
        GD_ERROR("Error during nfq_create_queue(): %i", strerror(errno));
        nfq_close(&m_Handle->get());
        return false;
    }

    if (nfq_set_mode(&m_QueueHandle->get(), NFQNL_COPY_PACKET, 0x5EE) < 0) {
        GD_ERROR("Can't set packet_copy mode: %i", strerror(errno));
        nfq_destroy_queue(&m_QueueHandle->get());
        nfq_close(&m_Handle->get());
        return false;
    }

    m_fd = nfq_fd(&m_Handle->get());
    if (m_fd < 0) {
        GD_ERROR("Failed to get file descriptor for NFQUEUE: %i", strerror(errno));
        nfq_destroy_queue(&m_QueueHandle->get());
        nfq_close(&m_Handle->get());
        return false;
    }

    GD_INFO("libnetfilter attacked");

    if (!PushMitigation<DnsBlock>())
        return false;
    return true;
}

bool NfqLayer::OnDetach() {
    // logfile.close();

    for (const auto& mitigation : m_Mitigations)
        mitigation->OnDetach();

    if (m_QueueHandle.has_value())
        nfq_destroy_queue(&m_QueueHandle->get());

    if (m_Handle.has_value())
        nfq_close(&m_Handle->get());

    return true;
}

void NfqLayer::OnUpdate(Timestep ts) {
    char buffer[0x1000] __attribute__((aligned));
    if (const int rv = static_cast<const int>(recv(m_fd, buffer, sizeof(buffer), 0)); rv >= 0)
        nfq_handle_packet(&m_Handle->get(), buffer, rv);
}