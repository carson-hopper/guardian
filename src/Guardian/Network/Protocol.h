#pragma once

#include "Guardian/Core/Base.h"

#include <netinet/ip.h>

enum Protocol: int8_t {
    PROTOCOL_UNKNOWN = -1,

    ICMP = IPPROTO_ICMP,
    IGMP = IPPROTO_IGMP,
    IPIP = IPPROTO_IPIP,
    TCP = IPPROTO_TCP,
    EGP = IPPROTO_EGP,
    PUP = IPPROTO_PUP,
    UDP = IPPROTO_UDP,
    IDP = IPPROTO_IDP,
    TP = IPPROTO_TP,
    DCCP = IPPROTO_DCCP,
    RSVP = IPPROTO_RSVP,
    GRE = IPPROTO_GRE,
    ESP = IPPROTO_ESP,
    AH = IPPROTO_AH,
    MTR = IPPROTO_MTP,
};