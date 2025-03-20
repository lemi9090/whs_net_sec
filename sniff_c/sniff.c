#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h> //주소변환 기능을 사용하는 헤더 

// 이더넷 헤더와 ip 헤더를 정의해 줘야 한다. 
// 스니핑 과정에서 패킷이 캡쳐된 후 버퍼에 올라간다. 
// 패킷을 캡쳐하는 과정은 pcap 라이브러리로 제어된다. 

void packet_capture(u_char *args, const struct pcap_pkthdr * header , const u_char *packet){
    
}
#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h> //주소변환 기능을 사용하는 헤더 

// 이더넷 헤더와 ip 헤더를 정의해 줘야 한다. 
// 스니핑 과정에서 패킷이 캡쳐된 후 버퍼에 올라간다. 
// 패킷을 캡쳐하는 과정은 pcap 라이브러리로 제어된다. 
// 1. 네트워크 디바이스 열기
// 2. 패킷 캡처 시작
// 3. pcap 핸들 닫기

typedef unsigned char u_char; // 1바이트 메모리를 사용할 때 양수만 사용하여 값을 저장   
typedef unsigned short u_short; // 2바이트 메모리를 사용할 때 양수만 사용하여 값을 저장 

struct ethernet_header
{
    u_char ethernet_Dst_addr[6];
    u_char ethernet_Src_addr[6];
    u_short ether_type; // 2바이트  // 프로토콜 타입 설정 
};

struct ipheader {
    unsigned char      iph_ihl:4,		// IP header length
                       iph_ver:4;		// IP version
    unsigned char      iph_tos;		// Type of service
    unsigned short int iph_len;		// IP Packet length (data + header)
    unsigned short int iph_ident;		// Identification
    unsigned short int iph_flag:3,	// Fragmentation flags
                       iph_offset:13;	// Flags offset
    unsigned char      iph_ttl;		// Time to Live
    unsigned char      iph_protocol;	// Protocol type
    unsigned short int iph_chksum;	// IP datagram checksum
    struct  in_addr    iph_sourceip;	// Source IP address
    struct  in_addr    iph_destip;	// Destination IP address
};

struct tcpheader {
    u_short t_sp;                   // source port
    u_short t_dp;                   // destination port
    u_short Seq;                    // sequence number
    u_short Ack_number;             // Acknowledgemnet number
    u_char  tcp_offx2;               // data offset, rsvd
    u_char  tcp_flags;

    #define TH_FIN  0x01
    #define TH_SYN  0x02
    #define TH_RST  0x04
    #define TH_PUSH 0x08
    #define TH_ACK  0x10
    #define TH_URG  0x20
    #define TH_ECE  0x40
    #define TH_CWR  0x80
    #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)

    u_short tcp_win;            //window size
    u_short checksum;            
    u_short urgent_pointer;     //urgent_pointer
};


void packet_capture(u_char* args, const struct pcap_pkthdr* header, const u_char* packet) {
	printf("Get packet!\n");
    struct ethernet_header *eth = (struct ethernet_header *)packet;
    if (ntohs(eth->ether_type) == 0x0800) {
        //ntohs = 네트워크 바이트 순서를 호스트 바이트 순서로 변환해준다. 
        struct ipheader * ip = (struct ipheader *)(packet + sizeof(struct ethernet_header));
        // ip의 시작점을 구하는 과정 
        // = packet은 이더넷 헤더의 시작위치를 반환 + 이더넷 헤더의 크기를 하면 ip 헤더의 시작위치를 구할 수 있다. 
        struct tcpheader *tcp = (struct tcpheader *)(packet + sizeof(struct ethernet_header) + ip -> iph_ihl *4);

        
        printf("       From: %s\n", inet_ntoa(ip->iph_sourceip));  
        printf("         To: %s\n", inet_ntoa(ip->iph_destip));    
	printf("   Protocol: TCP\n");
        printf("\n");
    }    
}

int main() {
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;
    struct bpf_program fp;

    char filter_exp[] = "tcp";
    bpf_u_int32 net =0;

    handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device: %s\n", errbuf);
        return 2; // 오류 코드 반환
    }

    pcap_compile(handle, &fp, filter_exp, 0, net);
    if(pcap_setfilter(handle, &fp) != 0){
        pcap_perror(handle, "Error");
        exit(EXIT_FAILURE);
    }

    pcap_loop(handle, 0, packet_capture, NULL);

    pcap_freecode(&fp);
    pcap_close(handle);
    return 0;
}
