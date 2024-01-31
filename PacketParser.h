#ifndef _PACKET_PARSER_H
#define _PACKET_PARSER_H

#endif

#include <iostream>
#include <arpa/inet.h>
#include <sstream>
#include <iomanip>

#include "Protocol.h"

void parse_packet(const struct pcap_pkthdr *header, const u_char *packet);