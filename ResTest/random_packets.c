/*
 * (c) 2008-2011 Daniel Halperin <dhalperi@cs.washington.edu>
 */
#include <linux/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <getopt.h>
#include <signal.h>

#include <fcntl.h>
#include <sys/time.h>
#include <sys/select.h>

#include <tx80211.h>
#include <tx80211_packet.h>

#include "util.h"
#include "iwl_connector.h"
#include "iwl_structs.h"
#define PAYLOAD_SIZE	256
#define SLOW_MSG_CNT 1
#define MAXELEMENTS 5120
#define BandNum 3
struct Queue{						//recv queue for storage
	int Qfront;						//before writing in file
	int Qrear;
	int Qlength;
	char *RECVBUF;
};								
char *tempbuf;						//temp buf for storage for a CSI smg

union ctrlval
{
	/* data */
	uint32_t monctrl;
	/* bit band */
	struct {
		/**** Byte 1 *****/
		uint8_t Rates 	:3;			//rate selection bits
		uint8_t Stream	:2;			//siso,mimo-2,mimo-3
		uint8_t Zeros	:3;			//3 zeros,no explanation
		/**** Byte 2 *****/
		uint8_t HTcfg	:1;			//HT = 1, Legacy rate =0
		uint8_t Moulcfg	:1;			//CCK = 1, OFDM = 0
		uint8_t GFcfg	:1;			//GreenField =1, Legacy = 0
		uint8_t BWcfg	:1;			//40MHz = 1, 20MHz = 0
		uint8_t DDBcfg	:1;			//DDBcfg = 1&BWcfg = 1,2*20MHz?
		uint8_t GIcfg	:1;			//shortGI(400ns) = 1, longGI(800ns) = 0
		uint8_t Ant1	:1;			//select Antenna 1
		uint8_t Ant2	:1;			//select Antenna 2
		/**** Byte 3 *****/
		uint8_t Ant3	:1;			//select Antenna 3
		uint8_t	emp1	:7;			
		/**** Byte 4 *****/
		uint8_t emp2	:8;			//two empty val = 0 for u32
		/*** 4 in total ***/
	}ratebit;
};


/******************************************************/
struct tx80211	tx;
struct tx80211_packet	tx_packet;
struct tx80211_packet	INJ_TX,MON_TX,HOP_TX,ACK_TX;
uint8_t *payload_buffer;
const u_char sendbuf[] = {14, 16, 18, 20};
int err = 0;
uint8_t *inj_payload;
uint8_t *mon_payload;
uint8_t *hop_payload;
uint8_t *ack_payload;
/* LORCON FUNCTONS */
static void init_lorcon();
static void usage(char *argv[]);
/* BUFFER QUEUE HANDLER FUNCTIONS */
void InitQueue(struct Queue* pQueue, int elements_num);
int IsEmpty(struct Queue* pQueue);
void EnQueue(struct Queue* pQueue, char* src, int size_num);
int EmpQueue(struct Queue* pQueue, int elements_num);
int LogQueue(struct Queue* pQueue, int elelength, FILE* logfile);
/* ERROR HANDLER FUNCTIONS */
void caught_signal(int sig);
void exit_program(int code);
void exit_program_err(int code, char* func);


static inline void payload_memcpy(uint8_t *dest, uint32_t length,
		uint8_t *buffer)
{
	memcpy(dest, buffer, length);
}


/* socket  variables*/
int SOCK_FD = -1;					// the socket
FILE* out = NULL;					//log file
int main(int argc, char** argv)
{
    /********new vars from data_packet.c*********/
    unsigned int chan,curchan;
    unsigned int MCS = 0;
    int BW = 0;
    int GI = 0;
	int HT = 0;
	int c;
	FILE *txrate;
	
    /* tx params */
	int num_packets = 10;
	uint32_t packet_size = 200;
	lorcon_packet_t *packet;
	lorcon_packet_t *inj_packet;
	lorcon_packet_t *mon_packet;
	lorcon_packet_t *hop_packet;
	lorcon_packet_t *ack_packet;
	
	uint32_t HOPTIME = 10;
	int32_t recvret, txret, writeret, selret;
	uint32_t mode = 0;
	uint32_t delay_us = 0;
	struct timespec begin, end, logstart, logcurr;
	int32_t diff;
	uint16_t logdiff;
	/* recv vars */
	char buf[4096];
	struct cn_msg *cmsg;
	unsigned short l, l2;
	int count = 0;
	int TIMOFLAG = 0;						//flag for timeout in recv
	char *File_name = NULL;					//log file name
	struct Queue* BUFQUEUE;
	struct iwl5000_bfee_notif *bfee;
	BUFQUEUE = malloc(sizeof(struct Queue));
	/* Select vars */
	int flags;								//fcntl flags
	/* Rate Ctrl */
	union  ctrlval NewMonCtrlVal, OldMonCtrlVal;
	NewMonCtrlVal.monctrl = 0x04101;				//default value
	OldMonCtrlVal.monctrl = 0;
	/* Init the Queue */
	InitQueue(BUFQUEUE,MAXELEMENTS);
	/* Parse arguments */
    while ((c = getopt(argc, argv, "h:i:c:m:b:g:n:d:a:s:f:")) != EOF) {
	switch (c) {
	case 'h': 
		if (sscanf(optarg, "%u", &HT) != 1){
		    printf("ERROR: Unable to parse HT mode \n");
		    return -1;
		}
	    break;
	case 'c':
        HOPTIME = atoi(optarg);
	    break;
	case 'm':
		if (sscanf(optarg, "%u", &MCS) != 1){
		    printf("ERROR: Unable to parse MCS idex\n");
		    return -1;
		}
		break;
    case 'b':
		if (sscanf(optarg, "%u", &BW) != 1){
		    printf("ERROR: Unable to parse bandwidth \n");
		    return -1;
		}
		break;
	case 'g':
		if (sscanf(optarg, "%u", &GI) != 1){
		    printf("ERROR: Unable to parse guard interval \n");
		    return -1;
		}
		break;
    case 'n':
		if (sscanf(optarg, "%u", &num_packets) != 1) {
		    printf("ERROR: Unable to parse number of packets\n");
		    return -1;
		}
		break;

    case 'd':
		if (sscanf(optarg, "%u", &delay_us) != 1) {
		    printf("ERROR: Unable to parse interframe interval\n");
		    return -1;
		}
		break;
	case 'a':
		if(sscanf(optarg, "%u", &mode) != 1){
			printf("ERROR: Unable to parse mode");
			return -1;
		} 
		break;
	case 's':
		if(sscanf(optarg, "%u", &packet_size) != 1){
			printf("ERROR: Unable to parse size of packets\n");
		    return -1;
		}
		break;
	case 'f':
		if(sscanf(optarg, "%s", &File_name) != 1){
			printf("ERROR: Unable to parse name of file\n");
		}
		out = fopen(&File_name,"w");
		if(!out){printf("ERROR: Unable to open file\n");}
		break;	
	case 'i':
		printf("ERROR: cannot parse the input\n");
		usage(argv);
		return -1;
		break;
	default:
		usage(argv);
		return -1;
		break;
	}
    }
	

	/* Generate packet payloads */
	printf("Generating packet payloads \n");
	// payload_buffer = (char* )malloc(PAYLOAD_SIZE);
	inj_payload = (char* )malloc(PAYLOAD_SIZE);
	mon_payload = (char* )malloc(PAYLOAD_SIZE);
	hop_payload = (char* )malloc(PAYLOAD_SIZE);
	ack_payload = (char* )malloc(PAYLOAD_SIZE);
	
	Generate_payloads(inj_payload, PAYLOAD_SIZE, INJ_PAKT);
	Generate_payloads(mon_payload, PAYLOAD_SIZE, MON_PAKT);
	Generate_payloads(hop_payload, PAYLOAD_SIZE, HOP_PAKT);
	Generate_payloads(ack_payload, PAYLOAD_SIZE, ACK_PAKT);

	printf("payloadbuffer is %d,%d,%d,%d\n",inj_payload[10],mon_payload[10],hop_payload[10],ack_payload[10]);
	/* Setup the interface for lorcon */
	printf("Initializing LORCON\n");
	init_lorcon();
	/* Setup the socket */
	SOCK_FD = open_iwl_netlink_socket();
	/* Set up the "caught_signal" function as this program's sig handler */
	signal(SIGINT, caught_signal);
	/* Allocate packet */
	packet = Allocate_packet(packet_size);
	if (!packet) {
		perror("malloc packet");
		exit(1);
	}

	inj_packet = Allocate_packet(sizeof(*inj_packet) + packet_size);
	// mon_packet = Allocate_packet(sizeof(*mon_packet) + packet_size);
	hop_packet = Allocate_packet(sizeof(*hop_packet) + packet_size);
	ack_packet = Allocate_packet(sizeof(*ack_packet) + packet_size);

	INJ_TX.packet = (uint8_t *)inj_packet;
	INJ_TX.plen = sizeof(*inj_packet)+packet_size;

	// MON_TX.packet = (uint8_t *)mon_packet;
	// MON_TX.plen = sizeof(*mon_packet) + packet_size;

	HOP_TX.packet = (uint8_t *)hop_packet;
	HOP_TX.plen = sizeof(*hop_packet) + packet_size;

	ACK_TX.packet = (uint8_t *)ack_packet;
	ACK_TX.plen = sizeof(*ack_packet) + packet_size;

	payload_memcpy(inj_packet->payload, packet_size, inj_payload);
	// payload_memcpy(mon_packet->payload, packet_size, mon_payload);
	payload_memcpy(hop_packet->payload, packet_size, hop_payload);
	payload_memcpy(ack_packet->payload, packet_size, ack_payload);

	/* Parse Rate */
	/* Default Value */
	NewMonCtrlVal.ratebit.Zeros = 	0;
	NewMonCtrlVal.ratebit.Stream = 	0;
	NewMonCtrlVal.ratebit.Moulcfg = 0;
	NewMonCtrlVal.ratebit.GFcfg = 	0;
	NewMonCtrlVal.ratebit.DDBcfg =	0;
	NewMonCtrlVal.ratebit.emp1 =	0;
	NewMonCtrlVal.ratebit.emp2 =	0;
	/* Input Value */
	NewMonCtrlVal.ratebit.Rates =	1;
	NewMonCtrlVal.ratebit.HTcfg =	HT;
	NewMonCtrlVal.ratebit.BWcfg = 	BW;
	NewMonCtrlVal.ratebit.GIcfg =	GI;
	NewMonCtrlVal.ratebit.Ant1 =	0;
	NewMonCtrlVal.ratebit.Ant2 =	1;
	NewMonCtrlVal.ratebit.Ant3 =	0;

	NewMonCtrlVal.monctrl = 0x4901;

	/* Set tx rate*/
	if((txrate = fopen("/sys/kernel/debug/ieee80211/phy0/iwlwifi/iwldvm/debug/monitor_tx_rate", "r+")) ==NULL){
		printf("ERROR:	Could not open rate debug file.\n");
	}
	fscanf(txrate,"0x%x",&OldMonCtrlVal.monctrl);
	printf("BEFORE:	0x%x\n",OldMonCtrlVal.monctrl);
	fprintf(txrate,"0x%x",NewMonCtrlVal.monctrl);
	fclose(txrate);
	/* Open Log File */

	/* Set channel by call shell */
	chan = 0;
	err = iwl_netlink_send(SOCK_FD, &sendbuf[chan], sizeof(u_char));
	curchan = tx80211_getchannel(&tx);
	printf("Start channel is %d\n",curchan);
	printf("mode is %d\t1 for INJECTOR,0 for MONITOR.\n", mode);
	/* INJECTOR */
	if(mode == 1) {
		printf("THIS IS INJECTOR\n");
		while(chan < BandNum) {
			TIMOFLAG = 0;
			count = 0;
			curchan = tx80211_getchannel(&tx);
			printf("Current channel is %d\n",curchan);
			while(1) {
				/* Receive from socket with infinite timeout */
				recvret = recv(SOCK_FD, buf, sizeof(buf), 0);
				if(recvret == -1) {
						perror("recv");
						exit(-1);
				} else
					break;
			}
			printf("TRANS START!\n");
			while (count * delay_us < 100000)
			{
				usleep(delay_us);
				txret = tx80211_txpacket(&tx, &INJ_TX);
				if (txret < 0) {
					fprintf(stderr, "Unable to transmit packet: %s\n",tx.errstr);
					exit(1);
				}
				++count;
				if(count % 100 == 0)
					printf("TRANS 100 packets SUCCESSFULL!\n");
			}
			usleep(delay_us);
			txret = tx80211_txpacket(&tx, &HOP_TX);
			chan++;
			if(chan==BandNum)
				chan = 0;
			err = iwl_netlink_send(SOCK_FD, &sendbuf[chan], sizeof(u_char));
		}
	}
	/* MONITOR */
	if(mode == 0) {
		printf("THIS IS MONITOR\n");
		//set socket nonblock 
    	flags = fcntl(SOCK_FD, F_GETFL, 0);  
    	fcntl(SOCK_FD, F_SETFL, flags|O_NONBLOCK);
		//select fd，避免线程吊死
		fd_set st_read_set;
		//设置select
		FD_ZERO(&st_read_set);
		FD_SET(SOCK_FD, &st_read_set);
		clock_gettime(CLOCK_MONOTONIC, &logstart);
		while(chan < BandNum) {
			struct timeval recv_timeout = {0,200000};
			count = 0;
			TIMOFLAG = 0;
			curchan = tx80211_getchannel(&tx);
			usleep(delay_us);
			txret = tx80211_txpacket(&tx, &INJ_TX);
			if (txret)
				printf("Transmitted a  TRIGGER packet on channel %d!\n", curchan);
			if (chan == 0)
				clock_gettime(CLOCK_MONOTONIC, &begin);
			//设置select
			FD_ZERO(&st_read_set);
			FD_SET(SOCK_FD, &st_read_set);
			while (!TIMOFLAG)
			{
				selret = select(SOCK_FD + 1, &st_read_set, NULL, NULL, &recv_timeout);
				switch (selret)	{
				case -1:
					printf("err");
					return -1;
				case 0:
					//time out
					TIMOFLAG = 1;
					printf("TIME OUT! CHANGE CHANNEL!\n");
					break;
				default:
					recvret = recv(SOCK_FD, buf, sizeof(buf), 0);
					if (recvret == -1) {
						perror("recv");
						exit(-1);
					}
					cmsg = NLMSG_DATA(buf);
					if (cmsg->data[0] == 0xbb) {
						clock_gettime(CLOCK_MONOTONIC, &logcurr);
						logdiff = (logcurr.tv_sec - logstart.tv_sec) * 1000 +
								  (logcurr.tv_nsec - logstart.tv_nsec + 500) / 1000000;
						/* the cmsg is bfee notification */
						bfee = (void *)&cmsg->data[1];
						bfee->bfee_count = logdiff;
						bfee->fake_rate_n_flags = sendbuf[chan];
						/* log data to tempbuf */
						l = (unsigned short)cmsg->len;
						l2 = htons(l);
						fwrite(&l2, 1, sizeof(unsigned short), out);
						writeret = fwrite(cmsg->data, 1, l, out);
						count++;
						if (count % 100 == 0)
							printf("LOG 100 packets SUCESSFUL!\n");								
						} else if (cmsg->data[0] == 0xc1) {
							/* the cmsg is payload */
							if(buf[100] == HOP_PAKT) {
								TIMOFLAG = 1;
								printf("Received a hop packet.\t");
							}
							break;
						}
				}
			}
			if(TIMOFLAG) {
				chan++;
				if(chan == BandNum) {
					chan = 0;
					clock_gettime(CLOCK_MONOTONIC, &end);
					diff = (end.tv_sec - begin.tv_sec) * 1000000 + 
							(end.tv_nsec - begin.tv_nsec + 500) / 1000;
					printf("ALL BANDS LAST %d us\n",diff);
				}
				err = iwl_netlink_send(SOCK_FD, &sendbuf[chan], sizeof(u_char));
			}
		}
	}
	return 0;
}
/* LORCON FUNCTONS */
static void init_lorcon()
{
	/* Parameters for LORCON */
	int drivertype = tx80211_resolvecard("iwlwifi");
	printf("driver type %d\n",drivertype);
	/* Initialize LORCON tx struct */
	if (tx80211_init(&tx, "wlan0", drivertype) < 0) {
		fprintf(stderr, "Error initializing LORCON: %s\n",
				tx80211_geterrstr(&tx));
		exit(1);
	}
	if (tx80211_open(&tx) < 0 ) {
		fprintf(stderr, "Error opening LORCON interface\n");
		exit(1);
	}

	/* Set up rate selection packet */
	tx80211_initpacket(&tx_packet);
	tx80211_initpacket(&INJ_TX);
	tx80211_initpacket(&MON_TX);
	tx80211_initpacket(&HOP_TX);
	tx80211_initpacket(&ACK_TX);
	
}

static void usage(char *argv[]) {
    printf("\t-h <HTmode>	        HT Mode select(HT-1 | Legacy-0)\n");
    printf("\t-c <count>          	Total hop times \n");
    printf("\t-m <MCS_index>        MCS index (0~7)\n");
    printf("\t-b <band_width>       Band width(0-20M | 1-40M)\n");
    printf("\t-g <guard_interval>   Guard interval\n");
    printf("\t-n <count>            Number of packets to send\n");
    printf("\t-d <delay>            Interframe delay\n");
	printf("\t-a <mode>            	Mode(INJ-1 | MON-0)\n");
	printf("\t-s <size>            	Packet size\n");
	printf("\t-a <mode>            	a=1 for first injector\n");
	printf("\t-f <file>            	log file\n");

    printf("\nExample:\n");
    printf("\t%s -c 10 -n 2 -d 100 -s 100 -a 1 \n", argv[0]);
}
/* BUFFER QUEUE HANDLER FUNCTIONS */
/* Init the queue */
void InitQueue(struct Queue* pQueue, int elements_num)
{
	pQueue->Qfront = 0;					//front of the array
	pQueue->Qrear = 0;					//end+1 of the array where a new element is insert
	pQueue->Qlength = 0;				//length count of CSI DATATYPE,Qlength+1 when a tmpbuf recorded
	pQueue->RECVBUF = malloc(sizeof(char)*elements_num);
	if(pQueue->RECVBUF == NULL)
		perror("RECVBUF Init:");
}
/* Check if the queue is empty */
/* 	1 for non-empty;
	0 for empty	*/
int IsEmpty(struct Queue* pQueue)
{
	if((pQueue->Qrear==0)&&(pQueue->Qlength==0))
		return 1;
	else return 0;
}
/* Insert a new cm_msg */
void EnQueue(struct Queue* pQueue, char* src, int size_num)
{
	memcpy(pQueue->RECVBUF+pQueue->Qrear,src,size_num);
	pQueue->Qrear += size_num;
	pQueue->Qlength += size_num/215;
}
/* Make the queue empty */
int EmpQueue(struct Queue* pQueue, int elements_num)
{
	if(IsEmpty(pQueue))
	{
		printf("It's a empty queue,no need to destroy.\n");
		return 1;
	}
	else
	{
		free(pQueue->RECVBUF);
		pQueue->Qfront = 0;					
		pQueue->Qrear = 0;					
		pQueue->Qlength = 0;
		pQueue->RECVBUF = malloc(sizeof(char)*elements_num);
		if(pQueue->RECVBUF == NULL)
		{
			perror("RECVBUF Init:");
			return 0;
		}
		return 1;	
	}
}
/* Log the queue to file */
int LogQueue(struct Queue* pQueue, int elelength, FILE* logfile)
{
	int logret = 0;
	if(logfile == NULL)
	{
		printf("NO SUCH FILE!\n");
		return 0;
	}
	logret = fwrite(pQueue->RECVBUF, 1, (pQueue->Qlength)*elelength, logfile);
	return logret;
}
/* ERROR HANDLER FUNCTIONS */
void caught_signal(int sig)
{
	fprintf(stderr, "Caught signal %d\n", sig);
	exit_program(0);
}

void exit_program(int code)
{
	if (out)
	{
		fclose(out);
		out = NULL;
	}
	if (SOCK_FD != -1)
	{
		close(SOCK_FD);
		SOCK_FD = -1;
	}
	exit(code);
}

void exit_program_err(int code, char* func)
{
	perror(func);
	exit_program(code);
}
