#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include "header.h"
#include "function.h"

void usage(){
    printf("usage:   airodump-yb <interface>\n");
    printf("example: airodump-yb mon0\n");
}

int main(int argc, char * argv[]){
    if(argc < 2){
        usage();
        exit(1);
    }
    init();

    // for test, pcap_open_offline
    // TODO: capture live packet
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_offline(argv[1], errbuf);
    if (handle == NULL) {
        fprintf(stderr, "couldn't open file %s: %s\n", argv[1], errbuf);
        return -1;
    }
    
    while(handle != NULL){
        struct pcap_pkthdr* header;
        const u_char* data;

        int res = pcap_next_ex(handle, &header, &data);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;

        int type = check_packet_type(data);
        switch (type){
        case BEACON_FRAME:
            save_Beacon_info(data);
            break;
        case PROBE_REQUEST:
            save_Probe_info(data, PROBE_REQUEST);
            break;
        case PROBE_RESPONSE:
            save_Probe_info(data, PROBE_REQUEST);
            break;
        case QOS_DATA:
            save_QoS_info(data, QOS_DATA);
        case QOS_NULL:
            save_QoS_info(data, QOS_NULL);
        default:
            break;
        }
        show_airodump();
    }
    return 0;
}
