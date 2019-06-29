/*
 * (c) 2008-2011 Daniel Halperin <dhalperi@cs.washington.edu>
 */
#ifndef __UTIL_H__
#define __UTIL_H__

#include <sys/types.h>
#include <stdint.h>
#include <sys/socket.h>
#include <linux/netlink.h>

/*lorcon*/

#define INJ_PAKT 0
#define MON_PAKT 1
#define HOP_PAKT 2
#define ACK_PAKT 3

struct lorcon_packet
{
	__le16	fc;
	__le16	dur;
	u_char	addr1[6];
	u_char	addr2[6];
	u_char	addr3[6];
	__le16	seq;
	u_char	payload[0];
} __attribute__ ((packed));

typedef struct lorcon_packet lorcon_packet_t;
lorcon_packet_t *Allocate_packet(uint32_t packet_size);
void generate_payloads(uint8_t *buffer, size_t buffer_size);
void Generate_payloads(uint8_t *buffer,	size_t buffer_size,	int packet_type);
int get_mac_address(uint8_t *buf, const char *ifname);

/*netlink*/

#define IWL_NL_BUFFER_SIZE	4096

int open_iwl_netlink_socket();
void close_iwl_netlink_socket(int sock_fd);
int iwl_netlink_recv(int sock_fd, u_char **buf, int *len);
int iwl_netlink_send(int sock_fd, const u_char *buf, int len);
int netlink_recv(int sock_fd, u_char *buf, int *len);
struct iwl_netlink_msg {
	uint16_t length;	/* __le16 */
	uint8_t code;
	uint8_t payload[0];
} __attribute__ ((packed));


/* CHANNEL BUF FOR SHELL 

static char* CMD_BUF[] = {
	"iw wlan0 set channel 36 HT40+",
	"iw wlan0 set channel 44 HT40+",
	"iw wlan0 set channel 52 HT40+",
	"iw wlan0 set channel 60 HT40+",
	"iw wlan0 set channel 100 HT40+",
	"iw wlan0 set channel 108 HT40+",
	"iw wlan0 set channel 116 HT40+",
	"iw wlan0 set channel 124 HT40+",
	"iw wlan0 set channel 132 HT40+",
	"iw wlan0 set channel 149 HT40+",
	"iw wlan0 set channel 157 HT40+",
	};
*/
#endif	/* __UTIL_H__ */
