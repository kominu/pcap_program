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
#include <sys/ioctl.h>
#include <net/if.h>
#include <netdb.h>
#include <ctype.h>
#include <map>

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
pcap_dumper_t *dumpfile;
int s_rate;
int s_state;//0:通常、1:サンプリングモード
int mode_state;//offなら0、onなら1
map<string, int>iplist;
map<string, int>::iterator p_iplist;

/*
 * 直前のip, port, protocol, flag, 経過時間と比較し、
 * 送るパケットの圧縮をはかる
 */
//char pre_clip[2][16], pre_protocol[2][10], pre_flag[2][8];
char pre_tcp_syn[2][26], pre_tcp_ack[2][26], pre_tcp_synack[2][26], pre_tcp_other[2][26], pre_udp[2][26], pre_icmp[2][26], pre_other[2][26];
int pre_tcp_syn_time, pre_tcp_ack_time, pre_tcp_synack_time, pre_tcp_other_time, pre_udp_time, pre_icmp_time, pre_other_time;
//int pre_svport[2], pre_time[2];

int main(int argc, char *argv[]){
	char cap_name[20] = "cap_data.csv";
	char err_name[20] = "err_data.csv";
	char pcap_name[20] = "log.pcap";
	char *dev, errbuf[PCAP_ERRBUF_SIZE], hostname[256];
	int port = 20000;
	int send_port = 30000;
	//char *sock_ip = "54.64.112.212";
	//char *sock_ip = "172.31.19.205";//aws server1
	//char *sock_ip = "172.31.30.244";//aws proxy
	//char *dst_ip = "119.172.116.86";
	//char *dst_ip = "172.31.19.205";//aws server1
	//char *dst_ip = "172.31.30.244";//aws proxy
	char *sock_ip, *dst_ip;
	pcap_t *handle;
	struct pcap_pkthdr header;
	//struct in_addr ip_addr;
	struct hostent *host;
	char message[256];
	char filter_exp[] = "(not udp src port 20000)";
	char filter_exp2[128];
	//char filter_exp[] = "";
	struct bpf_program fp;
	socklen_t addrlen;
	struct ifreq ifr;
	/* const u_char *packet; */
	switch(argc){
		case 1:
			mode_state = 1;
			s_state = 0;
			break;
		case 2:
			if(strcmp(argv[1], "-s") == 0){
				mode_state = 1;
				s_state = 1;
				s_rate = 10;
			}else{
			mode_state = 0;
			s_state = 0;
			}
			break;
		case 3:
			if(strcmp(argv[1], "-s") == 0){
				mode_state = 1;
				s_state = 1;
				s_rate = atoi(argv[2]);
			}else if(strcmp(argv[2], "-s") == 0){
				mode_state = 0;
				s_state = 1;
				s_rate = 10;
			}else{
				mode_state = 0;
				s_state = 0;
			}
			break;
		case 4:
			if(strcmp(argv[2], "-s") == 0){
				mode_state = 1;
				s_state = 1;
				s_rate = atoi(argv[3]);
			}else if(strcmp(argv[3], "-s") == 0){
				mode_state = 0;
				s_state = 1;
				s_rate = 10;
			}else{
				cout << "引数が多すぎます" << endl;
				exit(1);
			}
			break;
		case 5:
			if(strcmp(argv[3], "-s") == 0){
				mode_state = 0;
				s_state = 1;
				s_rate = atoi(argv[4]);
			}else{
				cout << "引数が多すぎます" << endl;
				exit(1);
			}
			break;
		default:
			cout << "引数が多すぎます" << endl;
			exit(1);
	}
	if(mode_state == 1) cout << "online mode" << endl;
	else cout << "offline mode" << endl;
	if(s_state == 1) cout << "sampling mode, rate : " << s_rate << endl;
	
	/* pre_*を初期化 */

	strcpy(pre_tcp_syn[0], "0");
	strcpy(pre_tcp_ack[0], "0");
	strcpy(pre_tcp_synack[0], "0");
	strcpy(pre_tcp_other[0], "0");
	strcpy(pre_udp[0], "0");
	strcpy(pre_icmp[0], "0");
	strcpy(pre_other[0], "0");
	strcpy(pre_tcp_syn[1], "0");
	strcpy(pre_tcp_ack[1], "0");
	strcpy(pre_tcp_synack[1], "0");
	strcpy(pre_tcp_other[1], "0");
	strcpy(pre_udp[1], "0");
	strcpy(pre_icmp[1], "0");
	strcpy(pre_other[1], "0");
	pre_tcp_syn_time = pre_tcp_ack_time = pre_tcp_synack_time = pre_tcp_other_time = pre_udp_time = pre_icmp_time = pre_other_time = 0; 
	/*
	   strcpy(pre_clip[0], "0");
	   strcpy(pre_clip[1], "0");
	   strcpy(pre_protocol[0], "0");
	   strcpy(pre_protocol[1], "0");
	   strcpy(pre_flag[0], "0");
	   strcpy(pre_flag[1], "0");
	   pre_svport[0] = pre_svport[1] = pre_time[0] = pre_time[1] = 0;
	   */
	/* とにかくUDPで送る */
	sock = socket(AF_INET, SOCK_DGRAM, 0);
	gethostname(hostname, sizeof(hostname));
	host = gethostbyname(hostname);
	bzero((char *)&me, sizeof(me));
	bzero((char *)&distination, sizeof(distination));
	me.sin_family = distination.sin_family = AF_INET;
	me.sin_port = htons(port);
	distination.sin_port = htons(send_port);
	/* 続きはlookupnetの後に記述（ipアドレスが必要なため) */
	//bcopy(host->h_addr, (char *)&me.sin_addr, host->h_length);
	//if(connect(sock, (struct sockaddr *)&me, sizeof(me)) < 0){
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
	printf("%d\n", argc);

	/* ipアドレスを取得 */
	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);
	ioctl(sock, SIOCGIFADDR, &ifr);


	/* ネットワークアドレスとネットマスクを取得 */
	if(pcap_lookupnet(dev, &my_addr, &my_nmask, errbuf)<0){
		fprintf(stderr, "IPアドレスとネットマスクの取得に失敗しました%s\n", errbuf);
		//exit(1);
	}else{
		if(mode_state == 1) strcpy(my_ip_copy, inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
		else if(argc == 5){
			strcpy(my_ip_copy, argv[2]);
		}else if(argc == 4 && s_state == 1){
			 strcpy(my_ip_copy, argv[2]);
		}else if(argc == 3 && s_state == 0){
			 strcpy(my_ip_copy, argv[2]);
		}else strcpy(my_ip_copy, inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
		cout << "IP:" << my_ip_copy << endl;
		sprintf(filter_exp2, "%s and host %s", filter_exp, my_ip_copy);
	}

	/* socket設定の続き ipアドレスが必要なため */
	sock_ip = dst_ip = inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr);
	//strcpy(dst_ip, inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
	inet_aton(sock_ip, &me.sin_addr);
	inet_aton(dst_ip, &distination.sin_addr);
	bind(sock, (struct sockaddr *)&me, sizeof(me));

	/* ディバイスをオープン(非プロミスキャスモード) */
	if(mode_state == 1) handle = pcap_open_live(dev, 64, 1, 10000, errbuf);
	else handle = pcap_open_offline(argv[1], errbuf);
	if(handle == NULL){
		fprintf(stderr, "デバイス「%s」を開けません:%s\n", dev, errbuf);
		exit(1);
	}
	if(filter_exp2 == NULL) strcpy(filter_exp2, filter_exp);
	cout << "filtering exp : " << filter_exp2 << endl;
	if(pcap_compile(handle, &fp, filter_exp2, 0, my_addr) == -1){
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
	/* offlineかonlineかを送信 */
	if(mode_state == 0){ 
		if(sendto(sock, "offline", strlen("offline"), 0, (struct sockaddr *)&distination, sizeof(distination)) < 0){
			cerr << "error in sendto" << endl;
		}
	}

	//logファイルを開く
	dumpfile = pcap_dump_open(handle, pcap_name);
	if(dumpfile == NULL){
		fprintf(stderr, "pcap_nameを開けませんでした\n");
		return -1;
	}
	/* loop */
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
	char cmp_exp[21], charport[5];
	sprintf(charport, "%d", sv_port);
	strcpy(cmp_exp, cl_ip);
	strcat(cmp_exp, charport);

	int samplesec = 50;
	if(state == 0){
		//transmit

		if(strcmp(proto, "TCP") == 0){
			if(strcmp(flag, "SYN") == 0){
				if(strcmp(cmp_exp, pre_tcp_syn[0]) == 0){
					if(ptime <= pre_tcp_syn_time + samplesec){
						cout << "cut " << proto << flag << sv_port << ptime << endl;
						return 0;
					}
				}
				strcpy(pre_tcp_syn[0], cmp_exp);
				pre_tcp_syn_time = ptime;
				return 1;

			}else if(strcmp(flag, "ACK") == 0){
				if(strcmp(cmp_exp, pre_tcp_ack[0]) == 0){
					if(ptime <= pre_tcp_ack_time + samplesec*2){
						cout << "cut " << proto << flag << sv_port << ptime << endl;
						return 0;
					}
				}
				strcpy(pre_tcp_ack[0], cmp_exp);
				pre_tcp_ack_time = ptime;
				return 1;

			}else if(strcmp(flag, "SYN/ACK") == 0){
				if(strcmp(cmp_exp, pre_tcp_synack[0]) == 0){
					if(ptime <= pre_tcp_synack_time + samplesec){
						cout << "cut " << proto << flag << sv_port << ptime << endl;
						return 0;
					}
				}
				strcpy(pre_tcp_synack[0], cmp_exp);
				pre_tcp_synack_time = ptime;
				return 1;

			}else{
				if(strcmp(cmp_exp, pre_tcp_other[0]) == 0){
					if(ptime <= pre_tcp_other_time + samplesec){
						cout << "cut " << proto << flag << sv_port << ptime << endl;
						return 0;
					}
				}
				strcpy(pre_tcp_other[0], cmp_exp);
				pre_tcp_other_time = ptime;
				return 1;

			}
		}else if(strcmp(proto, "UDP") == 0){
			if(strcmp(cmp_exp, pre_udp[0]) == 0){
				if(ptime <= pre_udp_time + samplesec){
					cout << "cut " << proto << sv_port << ptime << endl;
					return 0;
				}

			}
			strcpy(pre_udp[0], cmp_exp);
			pre_udp_time = ptime;
			return 1;

		}else if(strcmp(proto, "ICMP") == 0){
			if(strcmp(cmp_exp, pre_icmp[0]) == 0){
				if(ptime <= pre_icmp_time + samplesec){
					cout << "cut " << proto << sv_port << ptime << endl;
					return 0;
				}
			}
			strcpy(pre_icmp[0], cmp_exp);
			pre_icmp_time = ptime;
			return 1;

		}else{
			if(strcmp(cmp_exp, pre_other[0]) == 0){
				if(ptime <= pre_other_time + samplesec){
					cout << "cut " << proto << sv_port << ptime << endl;
					return 0;
				}
			}
			strcpy(pre_other[0], cmp_exp);
			pre_other_time = ptime;
			return 1;

		}
	}else{
		//receive
		if(strcmp(proto, "TCP") == 0){
			if(strcmp(flag, "SYN") == 0){
				if(strcmp(cmp_exp, pre_tcp_syn[1]) == 0){
					if(ptime <= pre_tcp_syn_time + samplesec){
						cout << "cut " << proto << flag << sv_port << ptime << endl;
						return 0;
					}
				}
				strcpy(pre_tcp_syn[1], cmp_exp);
				pre_tcp_syn_time = ptime;
				return 1;

			}else if(strcmp(flag, "ACK") == 0){
				if(strcmp(cmp_exp, pre_tcp_ack[1]) == 0){
					if(ptime <= pre_tcp_ack_time + samplesec*2){
						cout << "cut " << proto << flag << sv_port << ptime << endl;
						return 0;
					}
				}
				strcpy(pre_tcp_ack[1], cmp_exp);
				pre_tcp_ack_time = ptime;
				return 1;

			}else if(strcmp(flag, "SYN/ACK") == 0){
				if(strcmp(cmp_exp, pre_tcp_synack[1]) == 0){
					if(ptime <= pre_tcp_synack_time + samplesec){
						cout << "cut " << proto << flag << sv_port << ptime << endl;
						return 0;
					}
				}
				strcpy(pre_tcp_synack[1], cmp_exp);
				pre_tcp_synack_time = ptime;
				return 1;

			}else{
				if(strcmp(cmp_exp, pre_tcp_other[1]) == 0){
					if(ptime <= pre_tcp_other_time + samplesec){
						cout << "cut " << proto << flag << sv_port << ptime << endl;
						return 0;
					}
				}
				strcpy(pre_tcp_other[1], cmp_exp);
				pre_tcp_other_time = ptime;
				return 1;

			}
		}else if(strcmp(proto, "UDP") == 0){
			if(strcmp(cmp_exp, pre_udp[1]) == 0){
				if(ptime <= pre_udp_time + samplesec){
					cout << "cut " << proto << sv_port << ptime << endl;
					return 0;
				}
			}
			strcpy(pre_udp[1], cmp_exp);
			pre_udp_time = ptime;
			return 1;

		}else if(strcmp(proto, "ICMP") == 0){
			if(strcmp(cmp_exp, pre_icmp[1]) == 0){
				if(ptime <= pre_icmp_time + samplesec){
					cout << "cut " << proto << sv_port << ptime << endl;
					return 0;
				}
			}
			strcpy(pre_icmp[1], cmp_exp);
			pre_icmp_time = ptime;
			return 1;

		}else{
			if(strcmp(cmp_exp, pre_other[1]) == 0){
				if(ptime <= pre_other_time + samplesec){
					cout << "cut " << proto << sv_port << ptime << endl;
					return 0;
				}
			}
			strcpy(pre_other[1], cmp_exp);
			pre_other_time = ptime;
			return 1;

		}
	}

}

int sampling(){
	if(s_state == 1){
		if(rand() % s_rate == 0) return 1;
		else return 0;
	}else return 1;
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
	if(sampling() == 0){
	}else{
		/* logファイルに書き込む */
		pcap_dump((unsigned char *)dumpfile, header, packet);

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

		string err_msg = "";
		static int count = 1;
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

			iplist[ip_src_copy]++;
			iplist[ip_dst_copy]++;

			if(strcmp(ip_src_copy, my_ip_copy) == 0){
				if(checkpre(ip_dst_copy, protocol_name, tcp_flag, ntohs(tcp->th_sport), e_time, 0)){
					cout << count << "-取得したパケット:" << protocol_name << "(" << c_length << "/" << length << ")bytes" << err_msg << endl;

					cout << "    ・From:" << inet_ntoa(ip->ip_src) << ":" << ntohs(tcp->th_sport) << "(" << iplist[ip_src_copy] << ")" << endl;
					cout << "    ・To  :" << inet_ntoa(ip->ip_dst) << ":" << ntohs(tcp->th_dport) << "(" << iplist[ip_dst_copy] << ")" << endl;
					cout << "    ・Time:" << e_time << "milisec" << endl;
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

					cout << "    ・From:" << inet_ntoa(ip->ip_src) << ":" << ntohs(tcp->th_sport) << "(" << iplist[ip_src_copy] << ")" << endl;
					cout << "    ・To  :" << inet_ntoa(ip->ip_dst) << ":" << ntohs(tcp->th_dport) << "(" << iplist[ip_dst_copy] << ")" << endl;
					cout << "    ・Time:" << e_time << "milisec" << endl;
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
				cerr << "src(" << ip_src_copy << "), dst(" << ip_dst_copy << ")" << endl;
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

	}


