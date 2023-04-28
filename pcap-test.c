#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#define ETHER_ADDR_LEN 6

typedef struct libnet_ethernet_hdr
{
    u_int8_t  ether_dhost[ETHER_ADDR_LEN];/* destination ethernet address */
    u_int8_t  ether_shost[ETHER_ADDR_LEN];/* source ethernet address */
    u_int16_t ether_type[2];                 /* protocol */
}_LEH;

void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

typedef struct {
    char* dev_;
} Param;

Param param = {
    .dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return false;
    }
    param->dev_ = argv[1];
    return true;
}

int main(int argc, char* argv[]) {


    if (!parse(&param, argc, argv))
        return -1;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }
        printf("%u bytes captured\n", header->caplen);

        _LEH eth;
        for (int i = 0; i < ETHER_ADDR_LEN; i++) {
            eth.ether_dhost[i] = packet[i];
        }

        for (int j = 0; j < ETHER_ADDR_LEN; j++) {
            eth.ether_shost[j] = packet[j+ETHER_ADDR_LEN];
        }

        for (int k = 0; k < 2; k++) {
            eth.ether_type[k] = packet[k+ETHER_ADDR_LEN*2];
        }

        printf("SRC MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
               eth.ether_dhost[0], eth.ether_dhost[1], eth.ether_dhost[2],
               eth.ether_dhost[3], eth.ether_dhost[4], eth.ether_dhost[5]);
        printf("DST MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
               eth.ether_shost[0], eth.ether_shost[1], eth.ether_shost[2],
               eth.ether_shost[3], eth.ether_shost[4], eth.ether_shost[5]);
        printf("Protocol: 0x%02x:0x%02x\n", eth.ether_type[0],eth.ether_type[1]);

        pcap_close(pcap);
    }
}
