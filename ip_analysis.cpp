#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <iostream>
#include <fstream>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include "e_struct.h"

using namespace std;

void ip_analysis(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void dump_ips();
	
typedef struct ips{
	char ip_name[20];
	int cnt;
}ips;

ips ip_addrs[1000000];
ips top3[3];
int ip_count = 0;
int state = 0;//0:通常 1:冗長モード
ofstream fout;

int main(int argc, char *argv[]){
	pcap_t *handle;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr header;
	char fname[30];

	if(argc >= 3){
		cout << "処理を開始" << endl;
		sprintf(fname, "result:%s.txt", argv[2]);
		fout.open(fname, ios_base::out);
		if(!fout){
			cout << "ファイルを開けません：" << fname << endl;
			exit(1);
		}
		if(argc == 4){
			if(strcmp(argv[3], "-i") == 0) state = 1;
		}
		if((handle = pcap_open_offline(argv[1], errbuf)) == NULL){
			fprintf(stderr, "pcap_open_offlineに失敗:%s\n", errbuf);
		}
		if(pcap_loop(handle, -1, ip_analysis, NULL)<0){
			fprintf(stderr, "pcap_loopに失敗:%s\n", errbuf);
			exit(1);
		}
		pcap_close(handle);
		dump_ips();
		fout.close();
		cout << "finish" << endl;
		return 0;
	}else{
		cout << "pcapファイルを指定してください" << endl;
		return -1;
	}
}

void ip_analysis(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
	const struct sniff_ethernet *ethernet;
	const struct sniff_ip *ip;
	//const struct sniff_tcp *tcp;
	#define SIZE_ETHERNET 14
	
	u_int size_ip;
	int i;
	if(ip_count > 1000000){
		cout << "too many ips" << endl;
		exit(1);
	}
	
	ethernet = (struct sniff_ethernet*)(packet);
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if(ip_count == 0){
		strcpy(ip_addrs[0].ip_name, inet_ntoa(ip->ip_src));
		ip_addrs[0].cnt = 1;
		strcpy(ip_addrs[1].ip_name, inet_ntoa(ip->ip_dst));
		ip_addrs[1].cnt = 2;
		ip_count = 2;
	}else if(ip_count > 10000){
		dump_ips();
		exit(1);
	}else{
		for(i = 0;i < ip_count+1;i++){
			if(strcmp(ip_addrs[i].ip_name, inet_ntoa(ip->ip_src)) == 0){
				ip_addrs[i].cnt++;
				break;
			}
			if(i == ip_count){
				ip_count++;
				strcpy(ip_addrs[ip_count].ip_name, inet_ntoa(ip->ip_src));
				ip_addrs[ip_count].cnt = 1;
				if(state == 1) cout << i << ":" << inet_ntoa(ip->ip_src) << endl;
			}
		}
		for(i = 0;i < ip_count+1;i++){
			if(strcmp(ip_addrs[i].ip_name, inet_ntoa(ip->ip_dst)) == 0){
				ip_addrs[i].cnt++;
				break;
			}
			if(i == ip_count){
				ip_count++;
				strcpy(ip_addrs[ip_count].ip_name, inet_ntoa(ip->ip_dst));
				ip_addrs[ip_count].cnt = 1;
				if(state == 1) cout << i << ":" << inet_ntoa(ip->ip_dst) << endl;
			}
		}
	}
}

void dump_ips(){
	int i;
	for(i = 0;i < 3;i++){
		top3[i].cnt = 0;
	}
	cout << "IPアドレス：回数" << endl;
	for(i = 0;i < ip_count;i++){
		if(top3[2].cnt < ip_addrs[i].cnt){
			if(top3[1].cnt < ip_addrs[i].cnt){
				if(top3[0].cnt < ip_addrs[i].cnt){
					strcpy(top3[2].ip_name, top3[1].ip_name);
					strcpy(top3[1].ip_name, top3[0].ip_name);
					strcpy(top3[0].ip_name, ip_addrs[i].ip_name);
					top3[2].cnt = top3[1].cnt;
					top3[1].cnt = top3[0].cnt;
					top3[0].cnt = ip_addrs[i].cnt;
				}else{
					strcpy(top3[2].ip_name, top3[1].ip_name);
					strcpy(top3[1].ip_name, ip_addrs[i].ip_name);
					top3[2].cnt = top3[1].cnt;
					top3[1].cnt = ip_addrs[i].cnt;
				}
			}else{
				top3[2].cnt = ip_addrs[i].cnt;
				strcpy(top3[2].ip_name, ip_addrs[i].ip_name);
			}
		}
	}
	for(i = 0;i < 3;i++){
		cout << i + 1 << "->" << top3[i].ip_name << ", " << top3[i].cnt << endl;
		fout << i + 1 << "->" << top3[i].ip_name << ", " << top3[i].cnt << endl;
	}
}
