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
/*
 * 直前のip, port, protocol, flag, 経過時間と比較し、
 * 送るパケットの圧縮をはかる
 */
char pre_clip[2][16], pre_protocol[2][10], pre_flag[2][8];
int pre_svport[2], pre_time[2];

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
	char filter_exp[] = "not port 22 and not port 20000";
	struct bpf_program fp;
	socklen_t addrlen;
	/* const u_char *packet; */

	/* pre_*を初期化 */
	strcpy(pre_clip[0], "0");
	strcpy(pre_clip[1], "0");
	strcpy(pre_protocol[0], "0");
	strcpy(pre_protocol[1], "0");
	strcpy(pre_flag[0], "0");
	strcpy(pre_flag[1], "0");
	pre_svport[0] = pre_svport[1] = pre_time[0] = pre_time[1] = 0;

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

	/* ディバイスをオープン(非プロミスキャスモード) */
	handle = pcap_open_live(dev, 64, 1, 10000, errbuf);
	if(handle == NULL){
		fprintf(stderr, "デバイス「%s」を開けません:%s\n", dev, errbuf);
		exit(1);
	}

	if(pcap_compile(handle, &fp, filter_exp, 0, my_addr) == -1){
		cerr << "cannot compile filter" << endl;
		return(2);
	}
	if(pcap_setfilter(handle, &fp) == -1){
		cerr << "cannot import filter " << endl;
		return(2);
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

int checkpre(char *cl_ip, char *proto, char *flag, int sv_port, int ptime, int state){
	if(state == 0){
		//transmit
		if(strcmp(cl_ip, pre_clip[0]) == 0 && strcmp(proto, pre_protocol[0]) == 0 && strcmp(flag, pre_flag[0]) == 0){
			if(sv_port == pre_svport[0]){
				if(strcmp(flag, "ACK") == 0 && ptime <= pre_time[0] + 400) cout << "cut1 " << proto << " " << flag << endl;
				else if(ptime <= pre_time[0] + 50) cout << "cut2 " << proto << " " << flag << endl;
				else{
					strcpy(pre_clip[0], cl_ip);
					strcpy(pre_protocol[0], proto);
					strcpy(pre_flag[0], flag);
					pre_svport[0] = sv_port;
					pre_time[0] = ptime;
					return 1;
				}
				return 0;
			}else if(sv_port -10 <= pre_svport[0] && sv_port + 10 >= pre_svport[0]){
				if(ptime <= pre_time[0] + 10) cout << "cut3 " << proto << " " << flag << endl;
				else{
					strcpy(pre_clip[0], cl_ip);
					strcpy(pre_protocol[0], proto);
					strcpy(pre_flag[0], flag);
					pre_svport[0] = sv_port;
					pre_time[0] = ptime;
					return 1;
				}
				return 0;
			}
		}else{	
			strcpy(pre_clip[0], cl_ip);
			strcpy(pre_protocol[0], proto);
			strcpy(pre_flag[0], flag);
			pre_svport[0] = sv_port;
			pre_time[0] = ptime;
			return 1;
		}
	}else{
		if(strcmp(cl_ip, pre_clip[1]) == 0 && strcmp(proto, pre_protocol[1]) == 0 && strcmp(flag, pre_flag[1]) == 0){
			if(sv_port == pre_svport[1]){
				if(strcmp(flag, "ACK") == 0 && ptime <= pre_time[1] + 300) cout << "cut1 " << proto << " " << flag << endl;
				else if(ptime <= pre_time[1] + 10) cout << "cut2 " << proto << " " << flag << endl;
				else{
					strcpy(pre_clip[1], cl_ip);
					strcpy(pre_protocol[1], proto);
					strcpy(pre_flag[1], flag);
					pre_svport[1] = sv_port;
					pre_time[1] = ptime;
					return 1;
				}
				return 0;
			}else if(sv_port -10 <= pre_svport[1] && sv_port + 10 >= pre_svport[1]){
				if(ptime <= pre_time[1] + 10) cout << "cut3 " << proto << " " << flag << endl;
				else{
					strcpy(pre_clip[1], cl_ip);
					strcpy(pre_protocol[1], proto);
					strcpy(pre_flag[1], flag);
					pre_svport[1] = sv_port;
					pre_time[1] = ptime;
					return 1;
				}
				return 0;
			}
		}else{	
			strcpy(pre_clip[1], cl_ip);
			strcpy(pre_protocol[1], proto);
			strcpy(pre_flag[1], flag);
			pre_svport[1] = sv_port;
			pre_time[1] = ptime;
			return 1;
		}
	}

}


void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {

	/* とりあえずコピペ */

	/* イーサネットヘッダは常にちょうど14バイト */
#define SIZE_ETHERNET 14

	const struct sniff_ethernet *ethernet;	/* イーサネットヘッダ */
	const struct sniff_ip *ip;		/* IPヘッダ */
	const struct sniff_tcp *tcp;		/* TCPヘッダ */
	//const char *payload;			/* パケットペイロード */

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
	//payload = (char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);

	/* コピペここまで */

	/*
	if(c_length < length){
		err_msg = " <<lack!";
	}
	*/

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
	//if(ntohs(tcp->th_sport) != 22 && ntohs(tcp->th_dport) != 22 && ntohs(tcp->th_sport) != 20000){
	if(ntohs(tcp->th_sport) != -1){

		strcpy(ip_src_copy, inet_ntoa(ip->ip_src));
		strcpy(ip_dst_copy, inet_ntoa(ip->ip_dst));

		if(strcmp(ip_src_copy, my_ip_copy) == 0){
			if(checkpre(ip_dst_copy, protocol_name, tcp_flag, ntohs(tcp->th_sport), e_time, 0)){
				cout << count << "-取得したパケット:" << protocol_name << "(" << c_length << "/" << length << ")bytes" << err_msg << endl;

				cout << "    ・From:" << inet_ntoa(ip->ip_src) << "(" << ntohs(tcp->th_sport) << ")" << endl;
				cout << "    ・To  :" << inet_ntoa(ip->ip_dst) << "(" << ntohs(tcp->th_dport) << ")" << endl;
				cout << "    ・Time:" << e_time << "sec" << endl;
				cout << "      flag:" << tcp_flag << endl;
				sprintf(pcap_data, "%d,%s,%d,%s,%s,%d,%d,%d,true,%s", count, protocol_name, c_length, ip_src_copy, ip_dst_copy, ntohs(tcp->th_sport), ntohs(tcp->th_dport), e_time, tcp_flag);
				cap_csv << pcap_data << endl;
				if(sendto(sock, pcap_data, strlen(pcap_data), 0, (struct sockaddr *)&distination, sizeof(distination)) < 0){
					cerr << "error in sendto" << endl;
				}
				count++;
			}
		}else if(strcmp(ip_dst_copy, my_ip_copy) == 0){
			if(checkpre(ip_src_copy, protocol_name, tcp_flag, ntohs(tcp->th_dport), e_time, 1)){

				cout << count << "-取得したパケット:" << protocol_name << "(" << c_length << "/" << length << ")bytes" << err_msg << endl;

				cout << "    ・From:" << inet_ntoa(ip->ip_src) << "(" << ntohs(tcp->th_sport) << ")" << endl;
				cout << "    ・To  :" << inet_ntoa(ip->ip_dst) << "(" << ntohs(tcp->th_dport) << ")" << endl;
				cout << "    ・Time:" << e_time << "sec" << endl;
				cout << "      flag:" << tcp_flag << endl;
				sprintf(pcap_data, "%d,%s,%d,%s,%s,%d,%d,%d,false,%s", count, protocol_name, c_length, ip_dst_copy, ip_src_copy, ntohs(tcp->th_dport), ntohs(tcp->th_sport), e_time, tcp_flag);
				cap_csv << pcap_data << endl;
				if(sendto(sock, pcap_data, strlen(pcap_data), 0, (struct sockaddr *)&distination, sizeof(distination)) < 0){
					cerr << "error in sendto" << endl;
				}
				count++;
			}
		}else{
			cerr << "Cannot find ip:" << my_ip_copy << endl;
			cerr << "src(" << inet_ntoa(ip->ip_src) << "), dst(" << inet_ntoa(ip->ip_dst) << ")" << endl;
		}

		/* 見栄えを良くするためここでヘッダ長のエラーを報告 */
		if (size_ip < 20) {
			cerr << "    --不正なIPヘッダ長:" << size_ip << "bytes--" << endl;
		}
		if (ip->ip_p == IPPROTO_TCP && size_tcp < 20) {
			cerr << "    --不正なTCPヘッダ長:" << size_tcp << "bytes--" << endl;
		}
		//if(payload != NULL) cout << payload << endl;
	}

}


