/*
    This file is part of Linux Application Firewall (LAF).

    Linux Application Firewall (LAF) is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    any later version.

    Linux Application Firewall (LAF) is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Linux Application Firewall (LAF).  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>            /* for NF_ACCEPT */
#include <arpa/inet.h>                  /* for inet_ntop(), inet_pton() */
#include <string.h>                     /* for memcpy(), strcmp() etc. */

#include <signal.h>

#include <libnetfilter_queue/libnetfilter_queue.h>

#define LINE_BUFFER_SIZE 1024
#define MAX_ALLOWED_WHIETLIST 100
#define MAX_PKT_BUFFER 4096

/* IP header */
struct sniff_ip {
    u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
    u_char  ip_tos;                 /* type of service */
    u_short ip_len;                 /* total length */
    u_short ip_id;                  /* identification */
    u_short ip_off;                 /* fragment offset field */
    #define IP_RF 0x8000            /* reserved fragment flag */
    #define IP_DF 0x4000            /* dont fragment flag */
    #define IP_MF 0x2000            /* more fragments flag */
    #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
    u_char  ip_ttl;                 /* time to live */
    u_char  ip_p;                   /* protocol */
    u_short ip_sum;                 /* checksum */
    struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
    #define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
    #define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
    u_short th_sport;               /* source port */
    u_short th_dport;               /* destination port */
    tcp_seq th_seq;                 /* sequence number */
    tcp_seq th_ack;                 /* acknowledgement number */
    u_char  th_offx2;               /* data offset, rsvd */
    #define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
    u_char  th_flags;
    #define TH_FIN  0x01
    #define TH_SYN  0x02
    #define TH_RST  0x04
    #define TH_PUSH 0x08
    #define TH_ACK  0x10
    #define TH_URG  0x20
    #define TH_ECE  0x40
    #define TH_CWR  0x80
    #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short th_win;                 /* window */
    u_short th_sum;                 /* checksum */
    u_short th_urp;                 /* urgent pointer */
};

/* Structure for whitelist entry */
struct laf_entry 
{
    char *ip_src;
    char *ip_dst;
    uint16_t port;
};

/* Print all whitelisted entries */
int print_allowed();
/* Print a single entry */
int print_entry(struct laf_entry *entry);
/* Load the whitelist into memory */
int read_whitelist();
/* load the config */
int load_config();
/* Process packet form the queue */
static u_int32_t process_pkt (struct nfq_data *tb, struct laf_entry *curr_entry);
/* Check if the whitelist contains this entry */
int check_whitelist(struct laf_entry *entry);
/* Callback for the packet */
static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
        struct nfq_data *nfa, void *data);
static void termination_handler(int signo);

/* Takes IP_SRC SRC_PORT, IP_DST DST_PORT and returns a string of the associated binary name with the socket. */
const char* net_to_pid_name(char* ip_src, uint16_t src_port, char* ip_dst, uint16_t dst_port);
