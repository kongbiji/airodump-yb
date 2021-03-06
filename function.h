#pragma once
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <map>
#include <unistd.h>
#include "header.h"

using namespace std;

map<MAC, Beacon_values> beacon_map;
map<MAC, Beacon_values>::iterator beacon_iter;
map<CONV_MAC, Probe_values> probe_map;
map<CONV_MAC, Probe_values>::iterator probe_iter;

MAC BROADCAST;

void * channel_hop(void * data){
    char command[50], chan_num[3], real_command[50];
    int CHAN_NUM[14]= {1,7,13,2,8,3,14,9,4,10,5,11,6,12};
    int i = 0; 

    memset(command, 0, sizeof(command));
    strcpy(command, "sudo iwconfig ");
    strcat(command, (char *)data );
    strcat(command, " channel ");

    while(1){
        real_command[0] = '\0';
        chan_num[0] = '\0';
        sprintf(chan_num, "%d", CHAN_NUM[i]);
        strcpy(real_command, command);
        strcat(real_command, chan_num);
        system(real_command);
        i++;
        if(i > 14){
            i = 0;
        }
        sleep(1.5);
    }

}
void init(){
    memcpy(BROADCAST.mac,"\xFF\xFF\xFF\xFF\xFF\xFF", sizeof(BROADCAST.mac));
}
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
    }else if(dot11->Frame_Control_Field.Type == 2){
        if(dot11->Frame_Control_Field.Subtype == 8 ){
            RETURN = QOS_DATA;
        }else if(dot11->Frame_Control_Field.Subtype == 12 || dot11->Frame_Control_Field.Subtype == 4){
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
        if(len != 0){
            memcpy(val.ssid, find_ssid+2, len);
        }
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
        memcpy(val.ssid, beacon_iter->second.ssid, sizeof(val.ssid));
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

    unsigned char * r_header_iter;
    r_header = (radiotap_header *)data;
    r_header_iter = (unsigned char *)(data + sizeof(radiotap_header));
    dot11 = (Dot11 *)(data + r_header->h_len);

    // save probe
    int type_num;
    memcpy(key.bssid, dot11->mac3, sizeof(dot11->mac3)); //set bssid
    switch (type){
    case 1:  // Probe request
        type_num = 0;
        memcpy(key.station, dot11->mac2, sizeof(dot11->mac2)); // set station
        break;
    case 2:  // Probe response
        type_num = 12;
        memcpy(key.station, dot11->mac1, sizeof(dot11->mac1)); // set station
        break;
    default:
        break;
    }

    unsigned char * find_probe = (unsigned char *)(data + r_header->h_len + sizeof(Dot11) + type_num);
    if( (int)find_probe[0] == 0 ){ // SSID parameter
        int len = (int)find_probe[1];
        if(len != 0){
            memcpy(val.probe, find_probe+2, len);
        }
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
        memcpy(val.probe, probe_iter->second.probe, sizeof(val.probe));
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

    unsigned char * r_header_iter;
    r_header = (radiotap_header *)data;
    r_header_iter = (unsigned char *)(data + sizeof(radiotap_header));
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
    printf("BSSID\t\t\tPWR\tBeacons\t  CH\t SSID\n\n");
    for(beacon_iter = beacon_map.begin();beacon_iter != beacon_map.end();beacon_iter++){
        print_MAC((uint8_t *)beacon_iter->first.mac);
        printf("\t-%d\t%d\t  %d\t %s\n", beacon_iter->second.PWR, beacon_iter->second.Beacons, beacon_iter->second.CH,beacon_iter->second.ssid);
    }

    printf("\n\nBSSID\t\t\tSTATION\t\t\tPWR\t  Frames   Probe\n\n");
    for(probe_iter = probe_map.begin();probe_iter != probe_map.end();probe_iter++){
        if(memcmp(probe_iter->first.bssid, BROADCAST.mac, sizeof(MAC)) == 0){
            printf("(not associated)");
        }else{
            print_MAC((uint8_t *)probe_iter->first.bssid);
        }printf("\t");
        print_MAC((uint8_t *)probe_iter->first.station);
        printf("\t-%d\t  %d\t   %s\n", probe_iter->second.PWR, probe_iter->second.Frames, probe_iter->second.probe);
    }
}
