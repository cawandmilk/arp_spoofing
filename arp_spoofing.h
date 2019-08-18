#pragma once

#ifndef ARP_SPOOFING_H
#define ARP_SPOOFING_H

#include <arpa/inet.h>
#include <net/if.h>
#include <pcap.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "./include/libnet/libnet-macros.h"
#include "./include/libnet/libnet-headers.h"

#define MAC_SIZE 6
#define IP_SIZE 4

#pragma pack(push, 1) // struture padding terminate
typedef struct addr_pair
{
    uint8_t  sdr_mac[MAC_SIZE];
    uint32_t sdr_ip;
    uint8_t  tgt_mac[MAC_SIZE];
    uint32_t tgt_ip;
} addr_pair;

typedef struct arp_packet {
    struct libnet_ethernet_hdr e;
    struct libnet_arp_hdr a;
    struct addr_pair p;
} arp_packet;
#pragma pack(pop)

void usage();
void Print(const uint8_t* packet, size_t size);
void GetSvrMACAddress(uint8_t* dst);
void GetSvrIPAddress(uint32_t* dst);

int is_ip_packet(const uint8_t* packet);
int is_broadcasting_packet(const uint8_t* packet);
void get_target_mac_from_arp_table(uint8_t* dst, const uint8_t* packet, addr_pair* address_table, int table_size);
void set_relay_packet(const uint8_t* packet, uint8_t* target_mac, uint8_t* my_mac);
int get_session_location(uint8_t* target_mac, addr_pair* address_table, int session_size);
void get_mac_from_ip(uint8_t* dst_mac, const char* ip);

void send_infection_packet(pcap_t* handle, const uint8_t* packet, arp_packet* arp_lists,
                           addr_pair* address_table, int session_size);
void send_relay_packet(pcap_t* handle, const uint8_t* packet, addr_pair* address_table, int session_size, int packet_size);

#endif // ARP_SPOOFING_H
