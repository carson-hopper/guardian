#include "gdpch.h"
#include "Network/Detection/UDP/DnsBlock.h"
#include "Guardian/Network/Http.h"

#include <netinet/udp.h>
#include <ldns/ldns.h>

std::unordered_map<std::string, std::vector<std::string>> DnsBlock::s_Domains;

bool DnsBlock::OnAttach() {
    // Http http("https://raw.githubusercontent.com");
    // http.GET("/stamparm/blackbook/master/blackbook.txt");
    //
    // if (http.GetCode() == CURLE_OK) {
    //     std::vector<std::string> temp;
    //     std::string token;
    //     while (std::getline(std::istringstream(http.GetBuffer()), token, '\n')) {
    //         temp.push_back(token);
    //     }
    //
    //     m_BlockedDomains = temp;
    //     m_LastCheckTime = Time::GetTime();
    // }

    return true;
}

std::tuple<std::string, std::vector<std::string>> DnsBlock::ParseDnsRequest(const Ref<Packet>& packet) {
    std::string domain;
    std::vector<std::string> ips;

    const auto* ip = packet->GetIpPacket()->GetIpHeader();

    const uint32_t dnsPayloadSize = packet->GetBuffer().Size + (ip->ihl * 4) + sizeof(udphdr);
    const uint8_t* dnsPayload = packet->GetBuffer().Data + (ip->ihl * 4) + sizeof(udphdr);

    ldns_pkt *pkt;
    const ldns_status status = ldns_wire2pkt(&pkt, dnsPayload, dnsPayloadSize);
    if (status == LDNS_STATUS_OK && ldns_pkt_qdcount(pkt) > 0) {
        const ldns_rr_list* answer = ldns_pkt_answer(pkt);

        if (const uint32_t answerCount = ldns_rr_list_rr_count(answer); answerCount >= 1) {
            for (size_t i = 0; i < answerCount; i++) {
                const ldns_rr *rr = ldns_rr_list_rr(answer, i);

                if (char* _domain = ldns_rdf2str(ldns_rr_owner(rr)); _domain != nullptr) {
                    domain = _domain;
                    domain = domain.substr(0, domain.find_last_of('.'));

                    if (char* _ip = ldns_rdf2str(ldns_rr_rdf(rr, 0)); _ip != nullptr) {
                        ips.emplace_back(_ip);
                        free(_ip);
                    }

                    free(_domain);
                }
            }
        }

    }

    return {domain, ips};
}

std::tuple<PacketAction, Buffer&> DnsBlock::OnUpdate(const Ref<Packet>& packet) {
    Buffer& buffer = packet->GetBuffer();
    auto* ip = reinterpret_cast<iphdr*>(buffer.Data);
    auto* udp = reinterpret_cast<udphdr*>(buffer.Data + (ip->ihl * 4));

    const uint8_t srcPort = ntohs(udp->source);
    const uint8_t dstPort = ntohs(udp->dest);

    if (srcPort == 53 || dstPort == 53) {
        if (auto [domain, ips] = ParseDnsRequest(packet); !ips.empty()) {
            s_Domains[domain] = ips;

            //ip->tot_len = htons(buffer.Size);
            //udp->len = htons(buffer.Size - (ip->ihl * 4));
            udp->check = 0;

            std::string rdata;
            for (const auto &it : ips) {
                rdata.append(it + ", ");
            }

            rdata = rdata.substr(0, rdata.find_last_of(','));

            GD_INFO("IP: {} -> {}, DNS Answer: {} -> {}", packet->GetIpPacket()->GetSourceIpStr(), packet->GetIpPacket()->GetDestinationIpStr(), domain, rdata);

            for (auto& it : m_BlockedDomains) {
                if (it == domain)
                    return {DROP, buffer};
            }
        }

    }

    return {ACCEPT, buffer};
}