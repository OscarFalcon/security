#include "pcap.h"


typedef struct address_t
{
	struct   addr ip;          //ip address
	struct   addr mac;         //mac address
	uint16_t port;             //port number

} address_t;


#define TIMING_CONTINUOUS 1	//dont wait for victim response, just blast packets their way
#define TIMING_DELAY 2			//just like continuous, except wait a little between packets
#define TIMING_REACTIVE 3		//will wait for victim response(with timeout), based on packets in log file
#define TIMING_WAIT 4			//wait for victim to respond before sending next packet.
#define TIMING_EXACT 5			//delay time based on time between packets in log file
#define TIMING_OTHER 6			

struct file_config_t
{
	char tcpfile[1024];     //tcp file name 
	address_t victim;       //victim address
	address_t attacker;     //attacker address
	address_t rvictim;    	//replay victim address
	address_t rattacker;    //replay attacker address
	address_t middle;       //man in the middle address
	char iface[32];       	//interface name
	char timing;            //timing setting (continuous,delay,etc)
};


struct network_t
{
	eth_t *ethernet;
	pcap_t *pcap;
};



#define MAX_PACKETS 1024
struct info_t
{
	struct file_config_t    config;						//file configuration
	struct network_t	 		network;						//network information 
	struct pcap_pkthdr   	*packet_headers[1024];	//packet headers
	u_char               	*packets[1024];			//packets 
	volatile int 				response_packets[1024];	//the number of packets to expect in return	
	volatile int 				response_bytes[1024];	//the number of bytes to expect in return
	unsigned int         	total_packets;				//current total of packets in array
	volatile uint32_t       ack;           			//attackers current ack number
	volatile uint32_t       seq;           			//attackers current seq number
	volatile unsigned int 	current_packet;
};


void init_info(struct info_t *info);
void print_packet(struct pcap_pkthdr* pheader,const u_char *pack);

