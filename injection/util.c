/*
 * (c) 2008-2011 Daniel Halperin <dhalperi@cs.washington.edu>
 */

#include "iwl_connector.h"

#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>


#include "util.h"
/* lorcon */
static inline uint32_t advance_lfsr(uint32_t lfsr)
{
	return (lfsr << 1) | (((lfsr >> 31) ^ (lfsr >> 29) ^ (lfsr >> 25) ^
				(lfsr >> 24)) & 1);
}

void generate_payloads(uint8_t *buffer, size_t buffer_size)
{
	uint32_t lfsr = 0x1f3d5b79;
	uint32_t i;
	for (i = 0; i < buffer_size; ++i) {
		lfsr = advance_lfsr(lfsr);
		lfsr = advance_lfsr(lfsr);
		lfsr = advance_lfsr(lfsr);
		lfsr = advance_lfsr(lfsr);
		lfsr = advance_lfsr(lfsr);
		lfsr = advance_lfsr(lfsr);
		lfsr = advance_lfsr(lfsr);
		lfsr = advance_lfsr(lfsr);
		buffer[i] = lfsr & 0xff;
	}
}

int get_mac_address(uint8_t *buf, const char *ifname)
{
	int fd;
	struct ifreq ifr;

	/* Open generic socket */
	fd = socket(PF_INET, SOCK_PACKET, htons(ETH_P_ALL));
	if (fd == -1) {
		fprintf(stderr, "Error opening socket on %s to get MAC.\n",
				ifname);
		return 1;
	}

	/* Store interface name */
	strcpy(ifr.ifr_name, ifname);

	/* Get Hardware Address (i.e., MAC) */
	if (-1 == ioctl(fd, SIOCGIFHWADDR, &ifr)) {
		fprintf(stderr, "Error calling SIOCGIFHWADDR to get MAC.\n");
		return 1;
	}

	/* Store it in the return buffer */
	memcpy(buf, ifr.ifr_hwaddr.sa_data, 6);

	/* Close the socket and return success */
	close(fd);
	return 0;
}

lorcon_packet_t *Allocate_packet(uint32_t packet_size)
{
	lorcon_packet_t *ret_packet;
	ret_packet = (lorcon_packet_t *)malloc(sizeof(lorcon_packet_t) + packet_size);
	//frame control
	ret_packet->fc = (0x08 /* Data frame */
					| (0x0 << 8) /* Not To-DS */);
	//duration
	ret_packet->dur = 0xffff;
	//address
	memcpy(ret_packet->addr1, "\x00\x16\xea\x12\x34\x56", 6);
	memcpy(ret_packet->addr2, "\x00\x16\xea\x12\x34\x56", 6);
	memcpy(ret_packet->addr3, "\xff\xff\xff\xff\xff\xff", 6);
	//sequence
	ret_packet->seq = 0;

	return ret_packet;
}

void Generate_payloads(uint8_t *buffer,	size_t buffer_size,	int packet_type)
{
	uint32_t i;
	switch(packet_type){
		case INJ_PAKT:
			for(i = 0; i < buffer_size; ++i){
				buffer[i] = INJ_PAKT;
			}
			break;
		case MON_PAKT:
			for(i = 0; i < buffer_size; ++i){
				buffer[i] = MON_PAKT;
			}
			break;
		case HOP_PAKT:
			for(i = 0; i < buffer_size; ++i){
				buffer[i] = HOP_PAKT;
			}
			break;
		case ACK_PAKT:
			for(i = 0; i < buffer_size; ++i){
				buffer[i] = ACK_PAKT;
			}
			break;
		default:
			printf("Wrong Packet type.\n");
	}
}

/* netlink */

static char netlink_buffer[IWL_NL_BUFFER_SIZE];
static uint32_t seq = 0;

int open_iwl_netlink_socket()
{
	/* Local variables */
	struct sockaddr_nl proc_addr, kern_addr; // addrs for recv, send, bind
	int sock_fd;

	/* Setup the socket */
	sock_fd = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_CONNECTOR);
	if (sock_fd == -1) {
		perror("socket");
		return -1;
	}

	/* Initialize the address structs */
	memset(&proc_addr, 0, sizeof(struct sockaddr_nl));
	proc_addr.nl_family = AF_NETLINK;
	proc_addr.nl_pid = getpid();			// this process' PID
	proc_addr.nl_groups = CN_IDX_IWLAGN;
	memset(&kern_addr, 0, sizeof(struct sockaddr_nl));
	kern_addr.nl_family = AF_NETLINK;
	kern_addr.nl_pid = 0;					// kernel
	kern_addr.nl_groups = CN_IDX_IWLAGN;

	/* Now bind the socket */
	if (bind(sock_fd, (struct sockaddr *)&proc_addr, sizeof(struct
					sockaddr_nl)) == -1) {
		close(sock_fd);
		perror("bind");
		return -1;
	}

	/* And subscribe to netlink group */
	int on = proc_addr.nl_groups;
	if (setsockopt(sock_fd, 270, NETLINK_ADD_MEMBERSHIP, &on, sizeof(on))) {
		close(sock_fd);
		perror("setsockopt");
		return -1;
	}

	return sock_fd;
}

void close_iwl_netlink_socket(int sock_fd)
{
	close(sock_fd);
}

int iwl_netlink_recv(int sock_fd, u_char **buf, int *len)
{
	int ret = recv(sock_fd, netlink_buffer, sizeof(netlink_buffer), 0);
	if (ret == -1) {
		perror("netlink recv");
		return ret;
	}

	/* Pull out the message portion and print some stats */
	struct cn_msg *cmsg = NLMSG_DATA(netlink_buffer);
/* 	printf("received %d bytes: id: %u val: %u seq: %u clen: %d\n", */
/* 			cmsg->len, cmsg->id.idx, cmsg->id.val, */
/* 			cmsg->seq, cmsg->len); */
	*buf = cmsg->data;
	*len = cmsg->len;

	return ret;
}	

int iwl_netlink_send(int sock_fd, const u_char *buf, int len)
{
	struct nlmsghdr *nlh;
	uint32_t size;
	int ret;
	u_char local_buf[IWL_NL_BUFFER_SIZE];
	struct cn_msg *m;

	/* Set up outer netlink message */
	size = NLMSG_SPACE(sizeof(struct cn_msg) + len);
	nlh = (struct nlmsghdr *)local_buf;
	nlh->nlmsg_seq = seq;
	nlh->nlmsg_pid = getpid();
	nlh->nlmsg_type = NLMSG_DONE;
	nlh->nlmsg_len = NLMSG_LENGTH(size - sizeof(*nlh));
	nlh->nlmsg_flags = 0;

	/* Set up inner connector message */
	m = NLMSG_DATA(nlh);
	m->id.idx = CN_IDX_IWLAGN;
	m->id.val = CN_VAL_IWLAGN;
	m->seq = seq;
	m->ack = 0;
	m->len = len;
	memcpy(m->data, buf, len);

	/* Increment sequence number */
	++seq;

	/* Send message */
	ret = send(sock_fd, nlh, size, 0);
	return ret;
}

int netlink_recv(int sock_fd, u_char *buf, int *len)
{
	int ret = recv(sock_fd, netlink_buffer, sizeof(netlink_buffer), 0);
	if (ret == -1) {
		perror("netlink recv");
		return ret;
	}

	/* Pull out the message portion and print some stats */
	struct cn_msg *cmsg = NLMSG_DATA(netlink_buffer);
/* 	printf("received %d bytes: id: %u val: %u seq: %u clen: %d\n", */
/* 			cmsg->len, cmsg->id.idx, cmsg->id.val, */
/* 			cmsg->seq, cmsg->len); */
	buf = cmsg->data;
	*len = cmsg->len;

	return ret;
}