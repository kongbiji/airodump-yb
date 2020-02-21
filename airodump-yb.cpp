#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include "header.h"
#include "function.h"
#include<time.h>

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

    clock_t CurTime, OldTime;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "couldn't open device %s: %s\n", argv[1], errbuf);
        return -1;
    }

    pthread_t p_thread;
    int thr_id;
    int status;
    char * p;
    strcpy(p, argv[1]);

    thr_id = pthread_create(&p_thread, NULL, channel_hop, (void *)p);
    if (thr_id < 0){
        perror("thread create error : ");
        exit(0);
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
        OldTime = clock();
        show_airodump();
        while (1){
            CurTime = clock();
            if (CurTime - OldTime > 33)
                break;
        }
    }
    pthread_join(p_thread, (void **)&status);
    return 0;
}
