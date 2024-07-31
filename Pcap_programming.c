#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h> //for memcpy
#include <arpa/inet.h> // for ntohs, inet_ntoa


typedef struct ethernet_header {
    uint8_t dst_mac[6]; //목적지 MAC주소
    uint8_t src_mac[6]; //출발지 MAC주소
    uint16_t type; //타입 (IPv4)
} ethernet_header; //14바이트

typedef struct ip_header {
    uint8_t version_hd; //버전 + 헤더길이
    uint8_t tos; //서비스 타입
    uint16_t total_length; //총 길이
    uint16_t id; //식별자
    uint16_t flags_offset; //플래그 & 오프셋
    uint8_t ttl; //TTL
    uint8_t protocol; //프로토콜
    uint16_t checksum; //헤더 체크섬
    uint32_t src_ip; //출발지 IP 주소
    uint32_t dst_ip; //목적지 IP 주소
} ip_header; //20바이트


typedef struct tcp_header {
    uint16_t src_port; //출발지 포트
    uint16_t dst_port; //목적지 포트
    uint32_t seq_num; //순서 번호
    uint32_t ack_num; //확인 응답 번호
    uint8_t offset_reserved; // 데이터 오프셋과 예약된 필드
    uint8_t flags; // 플래그
    uint16_t window_size; // 윈도우 크기
    uint16_t checksum; // 체크섬
    uint16_t urgent_pointer; // 긴급 포인터
} tcp_header; // 20바이트


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


void print_information(const uint8_t* packet) {
    ethernet_header eth;
    ip_header ip;
    tcp_header tcp;

    memcpy(&eth, packet, sizeof(ethernet_header));
    memcpy(&ip, packet + sizeof(ethernet_header), sizeof(ip_header));
    memcpy(&tcp, packet + sizeof(ethernet_header) + sizeof(ip_header), sizeof(tcp_header));


    // Ethernet Header 정보 출력
    printf("Ethernet Header src mac : %02x %02x %02x %02x %02x %02x\n", 
           eth.src_mac[0], eth.src_mac[1], eth.src_mac[2], 
           eth.src_mac[3], eth.src_mac[4], eth.src_mac[5]);
    printf("Ethernet Header dst mac : %02x %02x %02x %02x %02x %02x\n", 
           eth.dst_mac[0], eth.dst_mac[1], eth.dst_mac[2], 
           eth.dst_mac[3], eth.dst_mac[4], eth.dst_mac[5]);


    // IP Header 정보 출력
    printf("IP Header src ip : %d.%d.%d.%d\n", 
           (ip.src_ip & 0xFF), 
           (ip.src_ip >> 8) & 0xFF, 
           (ip.src_ip >> 16) & 0xFF, 
           (ip.src_ip >> 24) & 0xFF);

    printf("IP Header dst ip : %d.%d.%d.%d\n", 
           (ip.dst_ip & 0xFF), 
           (ip.dst_ip >> 8) & 0xFF, 
           (ip.dst_ip >> 16) & 0xFF, 
           (ip.dst_ip >> 24) & 0xFF);


    // TCP Header 정보 출력
    printf("TCP Header src port : %u\n", ntohs(tcp.src_port));
    printf("TCP Header dst port : %u\n", ntohs(tcp.dst_port));


    // Payload 정보 출력 (최대 20바이트)
    const uint8_t *payload = packet + sizeof(ethernet_header) + sizeof(ip_header) + sizeof(tcp_header);
    printf("Payload (Data): ");
    for (int i = 0; i < 20; i++) {
        printf("%02x ", payload[i]);
    }
    printf("\n\n");
}


int main(int argc, char* argv[]) {
    if (!parse(&param, argc, argv))
        return -1;

    char errbuf[PCAP_ERRBUF_SIZE];

    //패킷을 캡처하기 위한 핸들을 생성함.
    pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;
        const uint8_t* packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }

        printf("%u bytes captured\n", header->caplen);
        print_information(packet);  // 변경된 함수 이름

    }

    pcap_close(pcap);

    return 0;
}
