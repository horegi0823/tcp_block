#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <pthread.h>
#include <string.h>
#include <stdlib.h>

char errbuf[PCAP_ERRBUF_SIZE];
char* interface;
pcap_t* handle;
//uint8_t* block_msg="HTTP/1.1 404 Not Found\r\nServer: Apache\r\nContent-Length: 10\r\nKeep-Alive: timeout=5, max=100\r\nConnection: Keep-Alive\r\nContent-Type: text/html\r\n\r\nHello\r\n";

uint8_t* block_msg="HTTP/1.1 404 Not Found\r\nContent-Length: 5\r\n\r\nHello\r\n";

struct block_info{
	uint8_t packet[2000];
	int len;	
};

u_short ip_sum_calc(u_short len_ip_header, u_short * buff )
{
        u_short word16;
        u_int sum = 0;
        u_short i;
        // make 16 bit words out of every two adjacent 8 bit words in the packet
        // and add them up
        for( i = 0; i < len_ip_header; i = i+2 )
        {
                word16 = ( ( buff[i]<<8) & 0xFF00 )+( buff[i+1] & 0xFF );
                sum = sum + (u_int) word16;
        }
        // take only 16 bits out of the 32 bit sum and add up the carries
        while( sum >> 16 )
                sum = ( sum & 0xFFFF ) + ( sum >> 16 );
        // one's complement the result
        sum = ~sum;
       
        return ((u_short) sum);
}

struct pseudo_header{
	uint32_t source_address;
	uint32_t dest_address;
	uint8_t placeholder;
	uint8_t protocol;
	uint16_t tcp_length;
};

uint16_t tcp_check(uint16_t *ptr,int nbytes) {
        register long sum;
        unsigned short oddbyte;
        register short answer;
 
        sum=0;
        while(nbytes>1) {
                sum+=*ptr++;
                nbytes-=2;
        }
        if(nbytes==1) {
                oddbyte=0;
                *((uint8_t*)&oddbyte)=*(uint8_t*)ptr;
                sum+=oddbyte;
        }
 
        sum = (sum>>16)+(sum & 0xffff);
        sum = sum + (sum>>16);
        answer=(uint16_t)~sum;
       
        return(answer);
}

void* block(void* data){
	struct block_info *info=(struct block_info*)malloc(sizeof(struct block_info));
	info=(struct block_info*)data;
	int packet_len=info->len;
	uint8_t* packet=(uint8_t*)malloc(packet_len);
	memcpy(packet,info->packet,packet_len);
	free(info);

	struct ether_header *packet_ethh,*ethh;
	struct ip *packet_iph,*iph;
	struct tcphdr *packet_tcph,*tcph;

	//check if packet is ip
	packet_ethh=(struct ether_header*)packet;
	if(ntohs(packet_ethh->ether_type)!=ETHERTYPE_IP){free(packet);return NULL;}
	int eth_len=sizeof(struct ether_header);	

	//check if packet is tcp
	packet_iph=(struct ip*)(packet+eth_len);
	if(packet_iph->ip_p!=IPPROTO_TCP){free(packet);return NULL;}
	int ip_len=4*packet_iph->ip_hl;

	packet_tcph=(struct tcphdr*)(packet+eth_len+ip_len);
	int tcp_len=4*packet_tcph->th_off;
	int packeth_len=eth_len+ip_len+tcp_len;
	int msg_len=packet_len-eth_len-ip_len-tcp_len;
	
	printf("%d %d\n",packet_len,msg_len);

	if(ntohs(packet_tcph->th_dport)==80){//if packet is http_request
		//make forward_rst
		uint8_t* forward_rst=(uint8_t*)malloc(packeth_len);
		memcpy(forward_rst,packet,packeth_len);
	
		iph=(struct ip*)(forward_rst+eth_len);
		iph->ip_ttl=255;
		iph->ip_tos=44;
		tcph=(struct tcphdr*)(forward_rst+eth_len+ip_len);
		tcph->th_flags = TH_RST | TH_ACK;
		//int flagAddLen=(packet_tcph->th_flags & (TH_SYN | TH_FIN)) ? 1 : 0;
		int flagAddLen=0;
		if(msg_len==0)flagAddLen=1;
		tcph->th_seq=htonl(ntohl(packet_tcph->th_seq)+msg_len+flagAddLen);
		tcph->th_ack=htonl(ntohl(packet_tcph->th_ack));

		//ip_checksum
		iph->ip_sum=0;
		uint16_t ipdata[20];
		uint8_t *tmp=forward_rst+14;
		for(int i=0;i<20;i++)ipdata[i]=*(uint8_t*)tmp++;
		iph->ip_sum=htons(ip_sum_calc(20,ipdata));

		//tcp_checksum
		tcph->th_sum=0;
		struct pseudo_header *psh=(struct pseudo_header*)malloc(sizeof(struct pseudo_header));
		psh->source_address=inet_addr(inet_ntoa(iph->ip_src));
		psh->dest_address=inet_addr(inet_ntoa(iph->ip_dst));
		psh->placeholder=0;//reserved
		psh->protocol=6;//protocol number for tcp
		psh->tcp_length=htons(tcp_len);
	
		uint8_t *seudo=(uint8_t*)malloc(sizeof(struct pseudo_header)+tcp_len);
		memcpy(seudo,psh,sizeof(struct pseudo_header));
		memcpy(seudo+sizeof(struct pseudo_header),tcph,tcp_len);
		uint16_t checksum=tcp_check((uint16_t*)seudo,sizeof(struct pseudo_header)+tcp_len);
		tcph->th_sum=checksum;

		//send forward_rst
		if(pcap_sendpacket(handle,forward_rst,packeth_len)==-1){
			printf("forward_rst error\n");
			pcap_perror(handle,0);
			pcap_close(handle);
			exit(1);
		}
		free(forward_rst);

		//make 404 packet
		uint8_t* fake_packet=(uint8_t*)malloc(packeth_len+strlen(block_msg));
		memcpy(fake_packet,packet,packeth_len);
		memcpy(fake_packet+packeth_len,block_msg,strlen(block_msg));

		ethh=(struct ether_header*)fake_packet;
		memcpy(ethh->ether_dhost,packet_ethh->ether_shost,6);
    memcpy(ethh->ether_shost,packet_ethh->ether_dhost,6);

		iph=(struct ip*)(fake_packet+eth_len);
		iph->ip_src=packet_iph->ip_dst;
		iph->ip_dst=packet_iph->ip_src;
		iph->ip_len=htons(ip_len+tcp_len+strlen(block_msg));
		tcph=(struct tcphdr*)(fake_packet+eth_len+ip_len);
		tcph->th_seq=packet_tcph->th_ack;
		tcph->th_ack=htonl(ntohl(packet_tcph->th_seq)+msg_len+flagAddLen);
		tcph->th_flags = TH_ACK | TH_SYN;

		iph->ip_sum=0;
		tmp=fake_packet+14;
		for(int i=0;i<20;i++)ipdata[i]=*(uint8_t*)tmp++;
    iph->ip_sum=htons(ip_sum_calc(20,ipdata));

		tcph->th_sum=0;
    psh->source_address=inet_addr(inet_ntoa(iph->ip_src));
    psh->dest_address=inet_addr(inet_ntoa(iph->ip_dst));
    psh->placeholder=0;
    psh->protocol=6;
    psh->tcp_length=htons(tcp_len+strlen(block_msg));

    uint8_t* seudo2=(uint8_t*)malloc(sizeof(struct pseudo_header)+tcp_len+strlen(block_msg));
    memcpy(seudo2,psh,sizeof(struct pseudo_header));
    memcpy(seudo2+sizeof(struct pseudo_header),tcph,tcp_len);
		memcpy(seudo2+sizeof(struct pseudo_header)+tcp_len,block_msg,strlen(block_msg));
    checksum=tcp_check((uint16_t*)seudo2,sizeof(struct pseudo_header)+tcp_len+strlen(block_msg));
    tcph->th_sum=checksum;

		//send 404 page
		if(pcap_sendpacket(handle,fake_packet,packeth_len+strlen(block_msg))==-1){
      printf("fake_packet error\n");
      pcap_perror(handle,0);
      pcap_close(handle);
      exit(1);
    }

		//make backward_fin
		printf("let's make backward_fin\n");
		uint8_t* backward_fin=(uint8_t*)malloc(packeth_len);
		memcpy(backward_fin,packet,packeth_len);

		ethh=(struct ether_header*)backward_fin;
		memcpy(ethh->ether_dhost,packet_ethh->ether_shost,6);
  	memcpy(ethh->ether_shost,packet_ethh->ether_dhost,6);

		iph=(struct ip*)(backward_fin+eth_len);
		printf("before src:%s\n",inet_ntoa(iph->ip_src));
	  iph->ip_src=packet_iph->ip_dst;
  	iph->ip_dst=packet_iph->ip_src;
		printf("before src:%s\n",inet_ntoa(iph->ip_src));
		iph->ip_len=htons(ip_len+tcp_len);
		iph->ip_tos=44;
		iph->ip_ttl=255;

 		tcph=(struct tcphdr*)(backward_fin+eth_len+ip_len);
 		tcph->th_sport=packet_tcph->th_dport;
  	tcph->th_dport=packet_tcph->th_sport;
  	tcph->th_seq=htonl(ntohl(packet_tcph->th_ack)+strlen(block_msg));
  	//flagAddLen=(packet_tcph->th_flags & (TH_SYN | TH_FIN)) ? 1 : 0;
  	tcph->th_ack=htonl(ntohl(packet_tcph->th_seq)+msg_len+flagAddLen);
  	tcph->th_flags = TH_FIN | TH_ACK;
		
		//ip_checksum
  	iph->ip_sum=0;
		tmp=backward_fin+14;
		for(int i=0;i<20;i++)ipdata[i]=*(uint8_t*)tmp++;
	  iph->ip_sum=htons(ip_sum_calc(20,ipdata));

  	//tcp_checksum
  	tcph->th_sum=0;
  	psh->source_address=inet_addr(inet_ntoa(iph->ip_src));
  	psh->dest_address=inet_addr(inet_ntoa(iph->ip_dst));
  	psh->placeholder=0;
  	psh->protocol=6;
  	psh->tcp_length=htons(tcp_len);

  	memcpy(seudo,psh,sizeof(struct pseudo_header));
  	memcpy(seudo+sizeof(struct pseudo_header),tcph,tcp_len);
  	checksum=tcp_check((uint16_t*)seudo,sizeof(struct pseudo_header)+tcp_len);
  	tcph->th_sum=checksum;
		
  	//send backward_fin
  	if(pcap_sendpacket(handle,backward_fin,packeth_len)==-1){
    	printf("backward_fin error\n");
    	pcap_perror(handle,0);
    	pcap_close(handle);
    	exit(1);
  	}
  	free(backward_fin);
		free(psh);
		free(seudo);
		free(seudo2);
		free(packet);
		return NULL;
	}

	//if packet is no http_request
	//make forward_rst
	uint8_t* forward_rst=(uint8_t*)malloc(packeth_len);
	memcpy(forward_rst,packet,packeth_len);
	
	iph=(struct ip*)(forward_rst+eth_len);
	iph->ip_ttl=255;
	iph->ip_tos=44;
	tcph=(struct tcphdr*)(forward_rst+eth_len+ip_len);
	tcph->th_flags = TH_RST | TH_ACK;
	//int flagAddLen=(packet_tcph->th_flags & (TH_SYN | TH_FIN)) ? 1 : 0;
	int flagAddLen=0;
	if(msg_len==0)flagAddLen=1;
	tcph->th_seq=htonl(ntohl(packet_tcph->th_seq)+msg_len+flagAddLen);

	//ip_checksum
	iph->ip_sum=0;
	uint16_t ipdata[20];
	uint8_t *tmp=forward_rst+14;
	for(int i=0;i<20;i++)ipdata[i]=*(uint8_t*)tmp++;
	iph->ip_sum=htons(ip_sum_calc(20,ipdata));

	//tcp_checksum
	tcph->th_sum=0;
	struct pseudo_header *psh=(struct pseudo_header*)malloc(sizeof(struct pseudo_header));
	psh->source_address=inet_addr(inet_ntoa(iph->ip_src));
	psh->dest_address=inet_addr(inet_ntoa(iph->ip_dst));
	psh->placeholder=0;//reserved
	psh->protocol=6;//protocol number for tcp
	psh->tcp_length=htons(tcp_len);
	
	uint8_t *seudo=(uint8_t*)malloc(sizeof(struct pseudo_header)+tcp_len);
	memcpy(seudo,psh,sizeof(struct pseudo_header));
	memcpy(seudo+sizeof(struct pseudo_header),tcph,tcp_len);
	uint16_t checksum=tcp_check((uint16_t*)seudo,sizeof(struct pseudo_header)+tcp_len);
	tcph->th_sum=checksum;

	//send forward_rst
	if(pcap_sendpacket(handle,forward_rst,packeth_len)==-1){
		printf("forward_rst error\n");
		pcap_perror(handle,0);
		pcap_close(handle);
		exit(1);
	}
	free(forward_rst);

	//make backward_rst
	uint8_t* backward_rst=(uint8_t*)malloc(packeth_len);
	memcpy(backward_rst,packet,packeth_len);
	
	ethh=(struct ether_header*)backward_rst;
	memcpy(ethh->ether_dhost,packet_ethh->ether_shost,6);
	memcpy(ethh->ether_shost,packet_ethh->ether_dhost,6);
	
	iph=(struct ip*)(backward_rst+eth_len);
	iph->ip_src=packet_iph->ip_dst;
	iph->ip_dst=packet_iph->ip_src;
	iph->ip_tos=44;
	iph->ip_ttl=255;

	tcph=(struct tcphdr*)(backward_rst+eth_len+ip_len);
	tcph->th_sport=packet_tcph->th_dport;
	tcph->th_dport=packet_tcph->th_sport;
	tcph->th_seq=packet_tcph->th_ack;
	//flagAddLen=(packet_tcph->th_flags & (TH_SYN | TH_FIN)) ? 1 : 0;
	tcph->th_ack=htonl(ntohl(packet_tcph->th_seq)+msg_len+flagAddLen);
	tcph->th_flags = TH_RST | TH_ACK;

	//ip_checksum
	iph->ip_sum=0;
	tmp=backward_rst+14;
	for(int i=0;i<20;i++)ipdata[i]=*(uint8_t*)tmp++;
  iph->ip_sum=htons(ip_sum_calc(20,ipdata));
	
	//tcp_checksum
	tcph->th_sum=0;
	psh->source_address=inet_addr(inet_ntoa(iph->ip_src));
	psh->dest_address=inet_addr(inet_ntoa(iph->ip_dst));
	psh->placeholder=0;
	psh->protocol=6;
	psh->tcp_length=htons(tcp_len);

	memcpy(seudo,psh,sizeof(struct pseudo_header));
	memcpy(seudo+sizeof(struct pseudo_header),tcph,tcp_len);
	checksum=tcp_check((uint16_t*)seudo,sizeof(struct pseudo_header)+tcp_len);
	tcph->th_sum=checksum;

	//send backward_rst
	if(pcap_sendpacket(handle,backward_rst,packeth_len)==-1){
    printf("backward_rst error\n");
    pcap_perror(handle,0);
    pcap_close(handle);
    exit(1);
  }
  free(backward_rst);
	free(seudo);
	free(psh);
	free(packet);
}

int main(int argc,char** argv){
	if(argc!=2){
		printf("no argv!!\n");
		exit(1);
	}

	interface=argv[1];
	handle=pcap_open_live(interface,BUFSIZ,1,0,errbuf);
	if(handle==NULL){
		fprintf(stderr,"couldn't open device %s: %s\n",interface,errbuf);
		return -1;
	}

	while(1){
		struct pcap_pkthdr* header;
		const uint8_t* packet;
		int res=pcap_next_ex(handle,&header,&packet);
		if(res==0)continue;
		if(res==-1 || res==-2)break;		
	
		struct block_info* info=(struct block_info*)malloc(sizeof(struct block_info));
		memcpy(info->packet,packet,header->caplen);
		info->len=header->caplen;

		//thread create
		pthread_attr_t attr;
		pthread_attr_init(&attr);
		pthread_attr_setdetachstate(&attr,PTHREAD_CREATE_DETACHED);
	
		pthread_t thread;
		int thread_id=pthread_create(&thread,&attr,block,info);
		if(thread_id){
			fprintf(stderr,"pthread_create error\n");
			continue;
		}
		//block(info);
	}
	pcap_close(handle);
	return 0;
}
