#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>

#define ETHER_ADDR_LEN 6

typedef struct libnet_ethernet_hdr
{
    u_int8_t  ether_dhost[ETHER_ADDR_LEN];  //destination ethernet address
    u_int8_t  ether_shost[ETHER_ADDR_LEN]; // source ethernet address
    u_int16_t ether_type;                 // protocol
}_LEH;

void usage() {  //이 프로그램이 어떻게 사용되는지 출력하는 함수.
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

typedef struct {  //구조체 Param을 정의하고 dev_ 변수를 멤버로 가진다.
    char* dev_;
} Param;

Param param = {  //Param 형식의 변수 param을 정의하고, 초기값으로 dev_ 멤버를 NULL로 설정한다.
    .dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {  //디바이스 이름을 받아오는 함수. 구조체 변수 param, 인자의 개수 argc, 인자의 값 배열 argv[]
    if (argc != 2) {
        usage();
        return false; //만약 인자의 개수가 2가 아니면 usage() 함수를 호출하고 false를 반환한다.
    }
    param->dev_ = argv[1]; //그렇지 않으면 argv[1] 값을 param->dev_에 저장하고 true를 반환한다.
    return true;
}

int main(int argc, char* argv[]) {


    if (!parse(&param, argc, argv))  //먼저 parse() 함수를 호출하여 디바이스 이름을 받아온다.
        return -1;  //만약 parse() 함수가 false를 반환하면 -1을 반환하고 프로그램을 종료한다.

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);  //그렇지 않으면 디바이스에 대한 pcap_t 타입의 핸들을 얻는다.
    if (pcap == NULL) {  //만약 핸들을 얻지 못하면 에러 메시지를 출력하고 -1을 반환한다.
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;  //헤더 파일에 있는 구조체
        const u_char* packet; //함수를 호출하면 이 구조체에 패킷의 메타데이터가 저장됩니다.
        int res = pcap_next_ex(pcap, &header, &packet); //패킷 읽어들이기. 패킷의 길이를 반환함. 반환 값은 0, 1, -1 중 하나.
        if (res == 0) continue;  //0: timeout 발생. 루프를 계속 실행합니다.
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) { //res== -1인 경우, 패킷 읽기 도중 에러 발생.
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));  //에러 메시지를 출력하고 루프를 종료.
            break;
        }
        printf("%u bytes captured\n", header->caplen); //정상적으로 패킷을 읽어들인 경우, 해당 패킷의 크기를 출력.
	}

        _LEH eth; //구조체를 선언합니다.
        for (int i = 0; i < ETHER_ADDR_LEN; i++) {
            eth.ether_dhost[i] = packet[i];
        }

        for (int i = 0; i < ETHER_ADDR_LEN; i++) {
            eth.ether_shost[i] = packet[i+ETHER_ADDR_LEN];
        }

        eth.ether_type = ntohs((uint16_t)packet[22]);

        printf("SRC MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
               eth.ether_dhost[0], eth.ether_dhost[1], eth.ether_dhost[2],
               eth.ether_dhost[3], eth.ether_dhost[4], eth.ether_dhost[5]);
        printf("DST MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
               eth.ether_shost[0], eth.ether_shost[1], eth.ether_shost[2],
               eth.ether_shost[3], eth.ether_shost[4], eth.ether_shost[5]);
        printf("Protocol: 0x%04x\n", eth.ether_type);

    pcap_close(pcap);
    }
}
