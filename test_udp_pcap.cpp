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
#include <mysql/mysql.h>
#include <arpa/inet.h>

#define DBHOST "localhost"
#define DBUSER "pcap"
#define DBPASS "pcap"
#define DBNAME "pcap_db"

using namespace std;
#define MAX_LEN 256 // fgetsで読み込む最大文字数

/* C++とlibpcapでパケットキャプチャプログラムを書く */
/* CとC++の文法が混ざっているので治す必要あり(最初から?) */

ofstream cap_csv;//cap_csvファイルに書き込むようのオブジェクト
ofstream err_csv;//err_cav用
FILE *fp2;//popen用の一時的なポインタ
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void logRead(char *last, FILE *flog);
void logSend(const char *buf);

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
int d_state;//database:1, not database:0
MYSQL *conn;
int max_ip_count;
long old_e_time;
char ip_best[128];
time_t start_time, last_time;
char last_netstat[128];
const char *check_list[] = {"DROP", "SRC", "DST", "PROTO", "SPT", "DPT", "SYN", "ACK", "RST", "FIN"};
int sample_count;
time_t mytime[100];

/*
 * 直前のip, port, protocol, flag, 経過時間と比較し、
 * 送るパケットの圧縮をはかる
 */
//char pre_clip[2][16], pre_protocol[2][10], pre_flag[2][8];


int main(int argc, char *argv[]){
	char *dev, errbuf[PCAP_ERRBUF_SIZE], hostname[256];
	int port = 19998;
	int send_port = 30000;
	char *sock_ip, *dst_ip;
	pcap_t *handle;
	struct pcap_pkthdr header;
	struct hostent *host;
	char message[256];
	char filter_exp[] = "(not udp src port 19998)";
	char filter_exp2[128];
	struct bpf_program fp;
	socklen_t addrlen;
	struct ifreq ifr;

	sample_count = 0;

	max_ip_count = 0;
	old_e_time = 0;
	start_time = time(NULL);
	last_time = time(NULL);

	/* const u_char *packet; */
	switch(argc){
		case 1:
			mode_state = 1;
			s_state = 1;
			s_rate = 10;
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
			mode_state = 1;
			s_state = 0;
			s_rate = 1;
			//cout << "引数が多すぎます" << endl;
			//exit(1);
	}
	if(mode_state == 1) cout << "online mode" << endl;
	else cout << "offline mode" << endl;
	if(s_state == 1) cout << "sampling mode, rate : " << s_rate << endl;

	/* pre_*を初期化 */

	/* とにかくUDPで送る */
	sock = socket(AF_INET, SOCK_DGRAM, 0);
	gethostname(hostname, sizeof(hostname));
	host = gethostbyname(hostname);
	bzero((char *)&me, sizeof(me));
	bzero((char *)&distination, sizeof(distination));
	me.sin_family = distination.sin_family = AF_INET;
	me.sin_port = htons(port);
	distination.sin_port = htons(send_port);

	/* データ格納用のcsvファイルを開く */
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
		if(strcmp("172.31.19.205", my_ip_copy) == 0) sprintf(filter_exp2, "(not udp src port 19998) and (host %s)", my_ip_copy);
		else sprintf(filter_exp2, "%s and host %s", filter_exp, my_ip_copy);
	}

	/* socket設定の続き ipアドレスが必要なため */
	sock_ip = dst_ip = inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr);
	//strcpy(dst_ip, inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));

	inet_aton(sock_ip, &me.sin_addr);
	inet_aton(dst_ip, &distination.sin_addr);
	cout << "host: " << inet_ntoa(me.sin_addr) << ", " << ntohs(me.sin_port) << endl;
	if(bind(sock, (struct sockaddr *)&me, sizeof(me)) < 0){
		cout << "bind error" << endl;
		close(sock);
		return -1;
	}
	/* ディバイスをオープン(非プロミスキャスモード) */
	if(mode_state == 1) handle = pcap_open_live(dev, 64, 0, 100, errbuf);
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

	cout << "waiting for packets from client" << endl;
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

	/* pcaploopとlogreadをマルチプロセスで動かす */


	/* loop */
	start_time = time(NULL);
	if(pcap_loop(handle, 10, got_packet, NULL)<0){
	}
		
	last_time = time(NULL);

	cout << last_time - start_time << endl;

	pcap_close(handle);
	close(sock);

	cout << "finish" << endl;

	return 0;
}

int sampling(int count){
	if(s_state == 1){
		int sample_key = count % s_rate;
		if(sample_key  == 0) return(1);
		else{
			//cout << sample_key << endl;
			//cout << "sampled packets" << endl;
			return(0);
		}
	}else return(1);
}


void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
}
