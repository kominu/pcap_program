#include <cstdio>
#include <cstring>
#include <iostream>
#include <fstream>
#include <unistd.h>

using namespace std;
void readLog(const char *buf);

const char *check_list[] = {"DROP", "SRC", "DST", "PROTO", "SPT", "DPT", "SYN", "ACK", "RST", "FIN"};

int main(){
	
	//ifstream ifs("/var/log/iptables.log");
	char last_log[256];
	FILE *flog;
	int loopcount;
	int pid;

	pid = fork();
	switch(pid){
		case -1:
			cerr << "error in fork" << endl;
			break;
		case 0://child
			while(1){
				cout << "a" << endl;
			}
			break;
		default:
			loopcount = 0;

			if(!(flog = popen("sudo tail -n 1 /var/log/iptables.log", "r"))){
				cerr << "error in popen" << endl;
				return -1;
			}
			if(!fgets(last_log, 255, flog)){
				cerr << "error in fgets" << endl;
				return -1;
			}
			pclose(flog);


			while(1){
				cout << "b" << endl;
			}
			while(1){
				char new_log[256];
				if(!(flog = popen("tail -n 1 /var/log/iptables.log", "r"))){
					cerr << "error in popen" << endl;
					return -1;
				}
				if(!fgets(new_log, 255, flog)){
					cerr << "error in fgets" << endl;
					return -1;
				}
				if(strcmp(new_log, last_log) != 0){
					readLog(new_log);
					strcpy(last_log, new_log);
				}
				pclose(flog);
			}
			break;
	}
}


void readLog(const char *buf){
	char *separator = " ";
	char *split_str;
	int count2 = 0;
	char sport[6] = "";
	char dport[6] = "";
	char str[256];
	char str2[256] = "";
	char *saveptr;

	strcpy(str, buf);
	if(strstr(str, "DROP:")){
		int count = 0;
		split_str = strtok_r(str, separator, &saveptr);
		while(split_str != NULL){
			int j;
			for(j = 0;j < 10;j++){
				if(strstr(split_str, check_list[j])){
					if(strcmp(str2, "") != 0) strcat(str2, " ");
					strcat(str2, split_str);
				}
			}
			if(strncmp(split_str, "SPT=", 4) == 0){
				int i = 0;
				while(split_str[i]!='\0'){
					if(isdigit(split_str[i])!=0) sport[strlen(sport)] = split_str[i];
					i++;
				}
				cout << count2 << ":" << "src=" << sport << endl;
			}else if(strncmp(split_str, "DPT=", 4) == 0){
				int i = 0;
				while(split_str[i]!='\0'){
					if(isdigit(split_str[i])!=0) dport[strlen(dport)] = split_str[i];
					i++;
				}
				cout << count2 << ":" << "dst=" << dport << endl;
			}
			split_str = strtok_r(NULL, separator, &saveptr);
		}
		cout << count2 << ":" << str2 << endl;
	}else cout << "not iptables log found" << endl;
}
