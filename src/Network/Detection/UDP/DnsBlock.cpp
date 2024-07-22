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
    // if (http.GetStatus() == 200) {
    //     auto split = [](const std::string& text, const char delim) {
    //         std::string line;
    //         std::vector<std::string> vec;
    //         std::stringstream ss(text);
    //         while(std::getline(ss, line, delim))
    //             vec.push_back(line);
    //         return vec;
    //     };
    //     m_BlockedDomains = split(http.GetBuffer(), '\n');
    //     m_LastCheckTime = Time::GetTime();
    // }
    m_LastCheckTime = Time::GetTime();

    return true;
}

std::tuple<std::string, std::vector<std::string>> DnsBlock::ParseDnsRequest(Packet& packet) {
    const float time = Time::GetTime();
    if (const Timestep timestep = time - m_LastCheckTime; timestep.GetSeconds() >  30) {
        OnAttach();
    }

    std::string domain;
    std::vector<std::string> ips;

    const auto* ip = packet.GetIpPacket()->GetIpHeader();

    const uint32_t dnsPayloadSize = packet.GetBuffer().Size + (ip->ihl * 4) + sizeof(udphdr);
    const uint8_t* dnsPayload = packet.GetBuffer().Data + (ip->ihl * 4) + sizeof(udphdr);

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

PacketAction DnsBlock::OnUpdate(Packet& packet) {
    Buffer& buffer = packet.GetBuffer();
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

            // std::string rdata;
            // for (const auto &it : ips) {
            //     rdata.append(it + ", ");
            // }
            //
            // rdata = rdata.substr(0, rdata.find_last_of(','));
            //
            // GD_INFO("IP: {} -> {}, DNS Answer: {} -> {}", packet.GetIpPacket()->GetSourceIpStr(), packet.GetIpPacket()->GetDestinationIpStr(), domain, rdata);
            //
            // for (auto& it : m_BlockedDomains) {
            //     if (it == domain)
            //         return {DROP, buffer};
            // }
        }

    }

    return ACCEPT;
}