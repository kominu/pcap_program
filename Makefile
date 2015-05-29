CXX	= g++
LIBS	= -lpcap -lmysqlclient
CXXFLAGS= -Wall
LDFLAGS	= -L/usr/lib64/mysql

pcap: udp_pcap.cpp
	$(CXX) $^ -o $@ $(CXXFLAGS) $(LDFLAGS) $(LIBS)
