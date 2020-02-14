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
map<CONV_MAC, Probe_values> probe_map;
map<CONV_MAC, Probe_values>::iterator probe_iter;

// check Type/Subtpye
int check_packet_type(const unsigned char * data){
    radiotap_header * r_header = (radiotap_header *)malloc(sizeof(radiotap_header));
    Dot11 * dot11 = (Dot11 *)malloc(sizeof(Dot11));
    r_header = (radiotap_header *)data;
    dot11 = (Dot11 *)(data+r_header->h_len);
    int RETURN = -1;

    if(dot11->Frame_Control_Field.Type == 0){ // Management frame(type == 0)
        switch (dot11->Frame_Control_Field.Subtype){
        case 8:
            RETURN = BEACON_FRAME;
            break;
        case 4:
            RETURN = PROBE_REQUEST;
            break;
        case 5:
            RETURN = PROBE_RESPONSE;
        default:
            break;
        }
    }else if(dot11->Frame_Control_Field.Type == 1){
        if(dot11->Frame_Control_Field.Subtype == 8 ){
            RETURN = QOS_DATA;
        }else if(dot11->Frame_Control_Field.Subtype == 12){
            RETURN = QOS_NULL;
        }
    }
    return RETURN;
}
void print_MAC(uint8_t *addr){
    printf("%02X:%02X:%02X:%02X:%02X:%02X",
           addr[0],addr[1],addr[2],addr[3],
            addr[4],addr[5]);
}
void save_Beacon_info(const unsigned char * data){
    // for map
    MAC bssid;
    Beacon_values val;
    memset(val.ssid, 0, sizeof(val.ssid));
    beacon_iter = beacon_map.begin();

    radiotap_header * r_header = (radiotap_header *)malloc(sizeof(radiotap_header));
    Dot11 * dot11 = (Dot11 *)malloc(sizeof(Dot11 *));

    unsigned char * r_header_iter;
    r_header = (radiotap_header *)data;
    r_header_iter = (unsigned char *)(data + sizeof(radiotap_header));
    dot11 = (Dot11 *)(data + r_header->h_len);

    memcpy( bssid.mac, dot11->mac3, sizeof(bssid.mac));

    // save ssid
    unsigned char * find_ssid = (unsigned char *)(data + r_header->h_len + sizeof(Dot11) + 12);
    if( find_ssid[0] == 0 ){ // SSID parameter
        int len = find_ssid[1];
        memcpy(val.ssid, find_ssid+2, len);
    }
    
    // radiotap fields check
    if( r_header->presnt_flags.tsft == 1 ){
        r_header_iter = r_header_iter + sizeof(uint64_t);
    }
    if( r_header->presnt_flags.flags == 1 ){
        r_header_iter = r_header_iter + sizeof(uint8_t);
    }
    if( r_header->presnt_flags.rate == 1 ){
        r_header_iter = r_header_iter + sizeof(uint8_t);
    }
    if( r_header->presnt_flags.channel == 1 ){
        val.CH = ((int)(r_header_iter[0] | (r_header_iter[1] << 8)) - 2412) / 5 + 1;
        r_header_iter = r_header_iter + sizeof(uint32_t);
    }
    if( r_header->presnt_flags.fhss == 1 ){
        r_header_iter = r_header_iter + sizeof(uint8_t);
    }
    if( r_header->presnt_flags.dbm_antenna_sig == 1 ){
        val.PWR = ((int)r_header_iter[0]-1)^0xFF;
        r_header_iter = r_header_iter + sizeof(uint8_t);
    }

    beacon_iter = beacon_map.find(bssid);
    if(beacon_iter != beacon_map.end()){  // already saved AP, update info
        int num = beacon_iter->second.Beacons;
        beacon_iter->second = val;
        beacon_iter->second.Beacons = num + 1;
    }else{ 
        beacon_map.insert(pair<MAC, Beacon_values>(bssid, val));
    }
}

void save_Probe_info(const unsigned char * data, int type){
    CONV_MAC key;
    Probe_values val;
    memset(val.probe, 0, sizeof(val.probe));
    probe_iter = probe_map.begin();

    radiotap_header * r_header = (radiotap_header *)malloc(sizeof(radiotap_header));
    Dot11 * dot11 = (Dot11 *)malloc(sizeof(Dot11 *));

    int * r_header_iter;
    r_header = (radiotap_header *)data;
    r_header_iter = (int *)(data + sizeof(radiotap_header));
    dot11 = (Dot11 *)(data + r_header->h_len);

    // save probe
    unsigned char * find_probe = (unsigned char *)(data + r_header->h_len + sizeof(Dot11) + 12);
    if( find_probe[0] == 0 ){ // SSID parameter
        int len = find_probe[1];
        memcpy(val.probe, find_probe+2, len);
    }

    switch (type){
    case 1:  // Probe request
        memcpy(key.bssid,"(not associated)", 16); // set bssid
        memcpy(key.station, dot11->mac2, sizeof(dot11->mac2)); // set station
        /* code */
        break;
    case 2:  // Probe response
        memcpy(key.bssid, dot11->mac3, sizeof(dot11->mac3)); //set bssid
        memcpy(key.station, dot11->mac1, sizeof(dot11->mac1)); // set station
        break;
    default:
        break;
    }
    // radiotap fields check
    if( r_header->presnt_flags.tsft == 1 ){
        r_header_iter = r_header_iter + sizeof(uint64_t);
    }
    if( r_header->presnt_flags.flags == 1 ){
        r_header_iter = r_header_iter + sizeof(uint8_t);
    }
    if( r_header->presnt_flags.rate == 1 ){
        r_header_iter = r_header_iter + sizeof(uint8_t);
    }
    if( r_header->presnt_flags.channel == 1 ){
        val.CH = ((int)(r_header_iter[0] | (r_header_iter[1] << 8)) - 2412) / 5 + 1;
        r_header_iter = r_header_iter + sizeof(uint32_t);
    }
    if( r_header->presnt_flags.fhss == 1 ){
        r_header_iter = r_header_iter + sizeof(uint8_t);
    }
    if( r_header->presnt_flags.dbm_antenna_sig == 1 ){
        val.PWR = ((int)r_header_iter[0]-1)^0xFF;
        r_header_iter = r_header_iter + sizeof(uint8_t);
    }

    probe_iter = probe_map.find(key);
    if(probe_iter != probe_map.end()){  // already saved AP, update info
        int num = probe_iter->second.Frames;
        probe_iter->second = val;
        probe_iter->second.Frames = num + 1;
    }else{ 
        probe_map.insert(pair<CONV_MAC, Probe_values>(key, val));
    }
}

void save_QoS_info(const unsigned char * data, int type){
    CONV_MAC key;
    Probe_values val;
    memset(val.probe, 0, sizeof(val.probe));
    probe_iter = probe_map.begin();

    radiotap_header * r_header = (radiotap_header *)malloc(sizeof(radiotap_header));
    Dot11_data * dot11 = (Dot11_data *)malloc(sizeof(Dot11_data *));

    int * r_header_iter;
    r_header = (radiotap_header *)data;
    r_header_iter = (int *)(data + sizeof(radiotap_header));
    dot11 = (Dot11_data *)(data + r_header->h_len);

     switch (type){
    case 3:  // QoS Data
        memcpy(key.bssid, dot11->mac2, sizeof(dot11->mac2)); // set bssid
        memcpy(key.station, dot11->mac1, sizeof(dot11->mac1)); // set station
        /* code */
        break;
    case 4:  // QoS NULL
        memcpy(key.bssid, dot11->mac1, sizeof(dot11->mac1)); //set bssid
        memcpy(key.station, dot11->mac2, sizeof(dot11->mac2)); // set station
        break;
    default:
        break;
    }
    // radiotap fields check
    if( r_header->presnt_flags.tsft == 1 ){
        r_header_iter = r_header_iter + sizeof(uint64_t);
    }
    if( r_header->presnt_flags.flags == 1 ){
        r_header_iter = r_header_iter + sizeof(uint8_t);
    }
    if( r_header->presnt_flags.rate == 1 ){
        r_header_iter = r_header_iter + sizeof(uint8_t);
    }
    if( r_header->presnt_flags.channel == 1 ){
        val.CH = ((int)(r_header_iter[0] | (r_header_iter[1] << 8)) - 2412) / 5 + 1;
        r_header_iter = r_header_iter + sizeof(uint32_t);
    }
    if( r_header->presnt_flags.fhss == 1 ){
        r_header_iter = r_header_iter + sizeof(uint8_t);
    }
    if( r_header->presnt_flags.dbm_antenna_sig == 1 ){
        val.PWR = ((int)r_header_iter[0]-1)^0xFF;
        r_header_iter = r_header_iter + sizeof(uint8_t);
    }


    probe_iter = probe_map.find(key);
    if(probe_iter != probe_map.end()){  // already saved AP, update info
        int num = probe_iter->second.Frames;
        probe_iter->second = val;
        probe_iter->second.Frames = num + 1;
    }else{ 
        probe_map.insert(pair<CONV_MAC, Probe_values>(key, val));
    }

}

void show_airodump(){
    system("clear");
    printf("BSSID\t\t\tPWR\tBeacons\t   SSID\n");
    for(beacon_iter = beacon_map.begin();beacon_iter != beacon_map.end();beacon_iter++){
        printf("%02X:%02X:%02X:%02X:%02X:%02X",
           beacon_iter->first.mac[0],beacon_iter->first.mac[1],beacon_iter->first.mac[2],beacon_iter->first.mac[3],
            beacon_iter->first.mac[4],beacon_iter->first.mac[5]);
        printf("\t-%d\t%d\t   %s\n", beacon_iter->second.PWR, beacon_iter->second.Beacons, beacon_iter->second.ssid);
    }

    printf("\n\nBSSID\t\t\t\tSTATION\t\t\tPWR\t\t\tFrames\t\tProbe\n");
    for(probe_iter = probe_map.begin();probe_iter != probe_map.end();probe_iter++){
        printf("%02X:%02X:%02X:%02X:%02X:%02X",
           probe_iter->first.bssid[0],probe_iter->first.bssid[1],probe_iter->first.bssid[2],beacon_iter->first.mac[3],
            probe_iter->first.bssid[4],probe_iter->first.bssid[5]);
        printf("\t%02X:%02X:%02X:%02X:%02X:%02X",
           probe_iter->first.station[0],probe_iter->first.station[1],probe_iter->first.station[2],probe_iter->first.station[3],
            probe_iter->first.station[4],probe_iter->first.station[5]);
        printf("\t\t-%d\t\t\t%d\t\t%s\n", probe_iter->second.PWR, probe_iter->second.Frames, probe_iter->second.probe);
    }
}
