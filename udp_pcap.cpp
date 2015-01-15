#include "e_struct.h"
#include <cstdio>
#include <cstdlib>
#include <string>
#include <cstring>
#include <iostream>
#include <fstream>
#include <sstream>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <ctype.h>

using namespace std;
#define MAX_LEN 256 // fgetsで読み込む最大文字数

/* C++とlibpcapでパケットキャプチャプログラムを書く */
/* CとC++の文法が混ざっているので治す必要あり(最初から?) */

ofstream cap_csv;//cap_csvファイルに書き込むようのオブジェクト
ofstream err_csv;//err_cav用
FILE *fp2;//popen用の一時的なポインタ
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
long s_time;
bpf_u_int32 my_addr;
bpf_u_int32 my_nmask;
char my_ip_copy[32];
int sock, num;
struct sockaddr_in me, distination;

int main(void){
	char cap_name[20] = "cap_data.csv";
	char err_name[20] = "err_data.csv";
	char *dev, errbuf[PCAP_ERRBUF_SIZE], hostname[256];
	int port = 20000;
	//char *sock_ip = "54.64.112.212";
	char *sock_ip = "172.31.19.205";
	//char *dst_ip = "119.172.116.86";
	char *dst_ip = "172.31.19.205";
	pcap_t *handle;
	struct pcap_pkthdr header;
	struct in_addr ip_addr;
	struct hostent *host;
	char message[256];
	socklen_t addrlen;
	/* const u_char *packet; */

	/* とにかくUDPで送る */
	sock = socket(PF_INET, SOCK_DGRAM, 0);
	gethostname(hostname, sizeof(hostname));
	host = gethostbyname(hostname);
	bzero((char *)&me, sizeof(me));
	bzero((char *)&distination, sizeof(distination));
	me.sin_family = distination.sin_family = PF_INET;
	me.sin_port = distination.sin_port = htons(port);
	//bcopy(host->h_addr, (char *)&me.sin_addr, host->h_length);
	//if(connect(sock, (struct sockaddr *)&me, sizeof(me)) < 0){
	inet_aton(sock_ip, &me.sin_addr);
	inet_aton(dst_ip, &distination.sin_addr);
	bind(sock, (struct sockaddr *)&me, sizeof(me));
	//if(inet_aton(sock_ip, &me.sin_addr)){
		/*
 		* connectを使用するとsendtoで送る相手を指定できない
 		* sendやwriteであれば使用可
		if(connect(sock, (struct sockaddr *)&me, sizeof(me)) < 0){
			cerr << "cannot bind socket" << endl;
			exit(1);
		}
		*/
	//}
	
	/* データ格納用のcsvファイルを開く */
	cap_csv.open(cap_name, ios_base::out);//見やすくするため上書き設定
	err_csv.open(err_name, ios_base::out);
	if(!cap_csv){
		cerr << "ファイルを開けません:" << cap_name << endl;
		exit(1);/* プログラムを終了 */
	}
	if(!err_csv){
		cerr << "ファイルを開けません:" << err_name << endl;
		exit(1);
	}

	/* ディバイスを定義 */
	dev = pcap_lookupdev(errbuf);
	if(dev == NULL){
		fprintf(stderr, "デバイスが見つかりませんでした:%s\n", errbuf);
		exit(1); /* プログラムを終了させる */
	}
	printf("デバイス:%s\n", dev);

	/* ディバイスをオープン(非プロミスキャスモード) */
	handle = pcap_open_live(dev, 256, 0, 10000, errbuf);
	if(handle == NULL){
		fprintf(stderr, "デバイス「%s」を開けません:%s\n", dev, errbuf);
		exit(1);
	}

	/* IPアドレスとネットマスクを取得 */
	if(pcap_lookupnet(dev, &my_addr, &my_nmask, errbuf)<0){
		fprintf(stderr, "IPアドレスとネットマスクの取得に失敗しました%s\n", errbuf);
		exit(1);
	}else{
		ip_addr.s_addr = my_addr;
		//strcpy(my_ip_copy, inet_ntoa(ip_addr));
		strcpy(my_ip_copy, "172.31.19.205");
		cout << "IP:" << my_ip_copy << endl;
	}

	addrlen = sizeof(distination);
	if(recvfrom(sock, message, strlen(message), 0, (struct sockaddr *)&distination, &addrlen) > 0){
		cout << message << endl;
	} 

	/* キャプチャ */
	cout << "パケットキャプチャを開始" << endl;
	if(pcap_loop(handle, -1, got_packet, NULL)<0){
		fprintf(stderr, "キャプチャに失敗:%s\n", errbuf);
		exit(1);
	}
	pcap_close(handle);
	cap_csv.close();
	err_csv.close();
	close(sock);

	cout << "finish" << endl;

	return 0;
}

void set_dst(){
	char dst_ip[16];
	int dst_port;
	distination.sin_family = PF_INET;
	distination.sin_port = dst_port;
	distination.sin_addr.s_addr = inet_addr(dst_ip);
}
	

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {

	/* とりあえずコピペ */

	/* イーサネットヘッダは常にちょうど14バイト */
#define SIZE_ETHERNET 14

	const struct sniff_ethernet *ethernet;	/* イーサネットヘッダ */
	const struct sniff_ip *ip;		/* IPヘッダ */
	const struct sniff_tcp *tcp;		/* TCPヘッダ */
	const char *payload;			/* パケットペイロード */

	u_int size_ip;
	u_int size_tcp;

	/* ここまでコピペ */

	static int count = 1;
	string err_msg = "";
	int c_length = header->caplen;
	int length = header->len;
	if(!s_time){
		s_time = header->ts.tv_sec*1000 + header->ts.tv_usec/1000;
	}
	long e_time = header->ts.tv_sec*1000 + header->ts.tv_usec/1000 - s_time;
	char protocol_name[6];     
	char lsof[256] = "lsof -Fc -i:";
	char src_port[256] = {'\0'};
	int sport;
	int dport;
	char process[MAX_LEN];
	char ip_src_copy[32];
	char ip_dst_copy[32];
	char tcp_flag[16];
	char pcap_data[256];

	/* とりあえずコピペ */

	ethernet = (struct sniff_ethernet*)(packet);
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	/*
	   if (size_ip < 20) {
	   printf("--不正なIPヘッダ長:%ubytes--\n", size_ip);
	   }
	   */
	tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
	size_tcp = TH_OFF(tcp)*4;
	/*
	   if (size_tcp < 20) {
	   printf("不正なTCPヘッダ長:%ubytes\n", size_tcp);
	   }
	   */
	payload = (char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);

	/* コピペここまで */

	if(c_length < length){
		err_msg = " <<lack!";
	}

	/* プロトコルを判断する */	
	switch(ip->ip_p) {
		case IPPROTO_TCP:
			strcpy(protocol_name, "TCP");
			break;
		case IPPROTO_UDP:
			strcpy(protocol_name, "UDP");            
			break;
		case IPPROTO_ICMP:
			strcpy(protocol_name, "ICMP");            
			break;
		case IPPROTO_IP:
			strcpy(protocol_name, "IP");            
			break;
		default:
			strcpy(protocol_name, "Unknown");            
			break;
	}

	if(ip->ip_p == IPPROTO_TCP){
		if(tcp->th_flags & TH_FIN) strcpy(tcp_flag, "FIN");
		else if(tcp->th_flags & TH_RST) strcpy(tcp_flag, "RST");
		else if(tcp->th_flags & TH_ACK){
			if(tcp->th_flags & TH_SYN) strcpy(tcp_flag, "SYN/ACK");
			else strcpy(tcp_flag, "ACK");
		}
		else if(tcp->th_flags & TH_SYN) strcpy(tcp_flag, "SYN");
		else strcpy(tcp_flag, "missed flags");
	}else strcpy(tcp_flag, "");

	/* 以下コピペによるパケット分析 */

	/* Src、DstのIPアドレスとポート番号 */
	if(ntohs(tcp->th_sport) != 22 && ntohs(tcp->th_dport) != 22 && ntohs(tcp->th_dport) != 20000){
		cout << count << "-取得したパケット:" << protocol_name << "(" << c_length << "/" << length << ")bytes" << err_msg << endl;

		cout << "    ・From:" << inet_ntoa(ip->ip_src) << "(" << ntohs(tcp->th_sport) << ")" << endl;
		cout << "    ・To  :" << inet_ntoa(ip->ip_dst) << "(" << ntohs(tcp->th_dport) << ")" << endl;
		cout << "    ・Time:" << e_time << "sec" << endl;
		cout << "      flag:" << tcp_flag << endl;

		strcpy(ip_src_copy, inet_ntoa(ip->ip_src));
		strcpy(ip_dst_copy, inet_ntoa(ip->ip_dst));


		if(strcmp(ip_src_copy, my_ip_copy) == 0){
			sprintf(pcap_data, "%d,%s,%d,%s,%s,%d,%d,%d,true,%s", count, protocol_name, c_length, ip_src_copy, ip_dst_copy, ntohs(tcp->th_sport), ntohs(tcp->th_dport), e_time, tcp_flag);
			//pcap_data = to_string(count) + "," + protocol_name + "," + to_string(c_length) + "," + ip_src_copy + "," + ip_dst_copy + "," + to_string(ntohs(tcp->th_sport)) + "," + to_string(ntohs(tcp->th_dport)) + "," + to_string(e_time) + ",true";
			//pcap_data = protocol_name;
			cap_csv << pcap_data << endl;
			//write(sock, pcap_data.c_str(), strlen(pcap_data.c_str()));
			if(sendto(sock, pcap_data, strlen(pcap_data), 0, (struct sockaddr *)&distination, sizeof(distination)) < 0){
				cerr << "error in sendto" << endl;
			}
			count++;
		}else if(strcmp(ip_dst_copy, my_ip_copy) == 0){
			sprintf(pcap_data, "%d,%s,%d,%s,%s,%d,%d,%d,false,%s", count, protocol_name, c_length, ip_dst_copy, ip_src_copy, ntohs(tcp->th_dport), ntohs(tcp->th_sport), e_time, tcp_flag);
			//pcap_data = to_string(count) + "," + protocol_name + "," + to_string(c_length) + "," + ip_dst_copy + "," + ip_src_copy + "," + to_string(ntohs(tcp->th_dport)) + "," + to_string(ntohs(tcp->th_sport)) + "," + to_string(e_time) + ",false";
			//pcap_data = protocol_name;
			cap_csv << pcap_data << endl;
			//write(sock, pcap_data, strlen(pcap_data));
			if(sendto(sock, pcap_data, strlen(pcap_data), 0, (struct sockaddr *)&distination, sizeof(distination)) < 0){
				cerr << "error in sendto" << endl;
			}
			count++;
		}else{
			cerr << "Cannot find ip:" << my_ip_copy << endl;
			cerr << "src(" << inet_ntoa(ip->ip_src) << "), dst(" << inet_ntoa(ip->ip_dst) << ")" << endl;
		}

		/* 見栄えを良くするためここでヘッダ長のエラーを報告 */
		if (size_ip < 20) {
			cerr << "    --不正なIPヘッダ長:" << size_ip << "bytes--" << endl;
		}

		if (size_tcp < 20) {
			cerr << "    --不正なTCPヘッダ長:" << size_tcp << "bytes--" << endl;
		}
	}
}


