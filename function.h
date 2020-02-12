#pragma once
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <map>
#include "header.h"

using namespace std;

map<MAC, Beacon_values> beacon_map;
map<MAC, Beacon_values>::iterator beacon_iter;

void print_MAC(uint8_t *addr){
    printf(" >> %02X:%02X:%02X:%02X:%02X:%02X\n",
           addr[0],addr[1],addr[2],addr[3],
            addr[4],addr[5]);
}

// check Type/Subtpye
int check_packet_type(const unsigned char * data){
    radiotap_header * r_header = (radiotap_header *)malloc(sizeof(radiotap_header));
    Dot11 * dot11 = (Dot11 *)malloc(sizeof(Dot11));

    r_header = (radiotap_header *)data;
    dot11 = (Dot11 *)(data+r_header->h_len);
    int RETURN = 0;

    uint16_t type = dot11->Frame_Control_Field.Subtype;
    switch (type){
    case 0x0080:
        RETURN = BEACON_FRAME;
        break;
    case 0x0040:
        RETURN = PROBE_REQUEST;
        break;
    case 0x0050:
        RETURN = PROBE_RESPONSE;
    default:
        break;
    }

    return RETURN;
}

void save_Beacon_info(const unsigned char * data){

    // for map
    MAC bssid;
    Beacon_values val;

    radiotap_header * r_header = (radiotap_header *)malloc(sizeof(radiotap_header));
    Dot11 * dot11 = (Dot11 *)malloc(sizeof(Dot11 *));

    int * r_header_iter;
    r_header = (radiotap_header *)data;
    r_header_iter = (int *)(data + sizeof(radiotap_header));
    dot11 = (Dot11 *)(data + r_header->h_len);

    memcpy( bssid.mac, dot11->mac3, sizeof(bssid.mac));

    // radiotap fields check
    if( r_header->presnt_flags.tsft == 1 ){
        r_header_iter = r_header_iter + sizeof(uint64_t);
    }else if( r_header->presnt_flags.flags == 1 ){
        r_header_iter = r_header_iter + sizeof(uint8_t);
    }else if( r_header->presnt_flags.rate == 1 ){
        r_header_iter = r_header_iter + sizeof(uint8_t);
    }else if( r_header->presnt_flags.channel == 1 ){
        val.CH = *r_header_iter;
        r_header_iter = r_header_iter + sizeof(uint16_t);
    }else if( r_header->presnt_flags.fhss == 1 ){
        r_header_iter = r_header_iter + sizeof(uint8_t);
    }else if( r_header->presnt_flags.dbm_antenna_sig == 1 ){
        val.PWR = *r_header_iter;
        r_header_iter = r_header_iter + sizeof(uint8_t);
    }
    // TODO: find and insert map


}

void save_Probe_info(unsigned char * data){

}
