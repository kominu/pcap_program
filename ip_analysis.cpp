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
#include <map>

using namespace std;

void ip_analysis(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void dump_ips();
	
int ip_count = 0;
int state = 0;//0:通常 1:冗長モード 2:パイプモード
ofstream fout;
map<string, int>ips;
map<string, int>::iterator p_ips;
map<int, string, greater<int> >ips2;
map<int, string, greater<int> >::iterator p_ips2;
int rank;

int main(int argc, char *argv[]){
	pcap_t *handle;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr header;
	char fname[50];
	char pname[50];
	rank = 1;
	if(argc >= 3){
		cout << "処理を開始" << endl;
		sprintf(fname, "result/%s_ip.txt", argv[2]);
		fout.open(fname, ios_base::out);
		if(!fout){
			cout << "ファイルを開けません：" << fname << endl;
			exit(1);
		}
		if(argc == 4){
			if(strcmp(argv[3], "-i") == 0) state = 1;
			if(strcmp(argv[3], "-p") == 0) state = 2;
		}else if(argc == 5){
			if(strcmp(argv[4], "-p") == 0) state = 2;
			else if(strcmp(argv[3], "-p") == 0){
				 state = 2;
				rank = atoi(argv[4]);
			}
		}else if(argc == 6){
			if(strcmp(argv[4], "-p") == 0){
 state = 2;
				rank = atoi(argv[4]);
			}
		}
		if(argv[1][0] == '/' || argv[1][0] == '~') strcpy(pname, argv[1]);
		else sprintf(pname, "pcap_files/%s", argv[1]);
		if((handle = pcap_open_offline(pname, errbuf)) == NULL){
			fprintf(stderr, "pcap_open_offlineに失敗:%s\n", errbuf);
		}
		if(pcap_loop(handle, 200000, ip_analysis, NULL)<0){
			//200000回試行
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
	
	ethernet = (struct sniff_ethernet*)(packet);
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	
	ips[inet_ntoa(ip->ip_src)]++;
	if(state == 1) cout << ip_count++ << ":" << inet_ntoa(ip->ip_src) << endl;
}

void dump_ips(){
	int i;
	cout << "IPアドレス：回数" << endl;
	p_ips = ips.begin();
	while(p_ips != ips.end()){
		ips2.insert(pair<int, string>(p_ips->second, p_ips->first));
		p_ips++;
	}
	p_ips2 = ips2.begin();
	if(state == 2){
		for(i = 0;i < rank;i++){
			if(++p_ips2 == ips2.end()) break;
		}
		cout << p_ips2->first;
	}else{
		for(i = 0;i < 10;i++){
			cout << p_ips2->second << ":" << p_ips2->first << endl;
			fout << p_ips2->second << ":" << p_ips2->first << endl;
			
			p_ips2++;
		}
	}
}
