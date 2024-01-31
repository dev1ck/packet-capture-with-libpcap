#include "PacketParser.h"

void parse_packet(const struct pcap_pkthdr *header, const u_char *packet)
{
    const struct EtherHdr *ether_hdr = reinterpret_cast<const struct EtherHdr*>(packet);

    std::ostringstream dstream, sstream;
    dstream << std::hex << std::setfill('0');
    sstream << std::hex << std::setfill('0');
    for (int i = 0; i < 6; ++i)
    {
        dstream << std::setw(2) << static_cast<int>(ether_hdr->etherDhost[i]);
        sstream << std::setw(2) << static_cast<int>(ether_hdr->etherShost[i]);
        if (i < 5)
        {
            dstream << ":";
            sstream << ":";
        }
    }

    std::cout << sstream.str() + " -> " << dstream.str() << " : " ;
    std::cout << std::hex << std::setw(4) << std::setfill('0') 
        << static_cast<int>(ntohs(ether_hdr->etherType)) << std::endl;
}

int parse_ethernet_packet(const u_char *packet)
{

}
   
