#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>            /* for NF_ACCEPT */
#include <arpa/inet.h>                  /* for inet_ntop(), inet_pton() */
#include <string.h>                     /* for memcpy(), strcmp() etc. */

#include <libnetfilter_queue/libnetfilter_queue.h>

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

struct laf_entry 
{
    char *ip_src;
    char *ip_dst;
    uint16_t port;
};


struct laf_entry allowed[100];
int total_entries = 0;

int print_allowed()
{
    int i; 
    for(i = 0; i < total_entries; i++)
    {
        printf("allowing traffic to %s ", allowed[i].ip_dst);
        if(allowed[i].port != 0)
        {
            printf("on port %d", allowed[i].port);
        }
        printf("\n");
    }
    return 0;
}

int print_entry(struct laf_entry *entry)
{
    printf("'%s'\t", entry->ip_src);
    printf("'%s'\t", entry->ip_dst);
    printf("'%d'\n", entry->port);

    return 0;
}


int read_whitelist()
{

    int line_buff_size = 2000;
    FILE *fp;
    char buff[line_buff_size];

    fp = fopen("whitelist.txt", "r");


    if( fp == NULL ){
        fprintf(stderr, "Error opening the white list file (whitelist.txt).\n");
        return 1;
    }

    while (fgets(buff, line_buff_size, fp) != NULL)
    {   
        char *split_entry;
        split_entry = strtok(buff, " ");
        struct laf_entry entry;
        int c = 0;
        while(split_entry != NULL)
        {
            switch(c)
            {
                case 0:
                    entry.ip_dst = strdup(split_entry);
                    break;
                case 1:
                    entry.port = atoi(split_entry);
                    break;
                default:
                    fprintf(stderr, "Error reading config, too many tokens!");
                    return 2;
            }
            c++;
            split_entry = strtok(NULL, " ");
        }

        allowed[total_entries] = entry;
        total_entries++;
    }

    fclose(fp);

    return 0;
}


static u_int32_t process_pkt (struct nfq_data *tb, struct laf_entry *curr_entry)
{

    int id = 0;
    struct nfqnl_msg_packet_hdr *ph;
    int ret;
    unsigned char *data;

    ph = nfq_get_msg_packet_hdr(tb);
    if (ph) {
        id = ntohl(ph->packet_id);
        printf("hw_protocol=0x%04x hook=%u id=%u \n",
                ntohs(ph->hw_protocol), ph->hook, id);
    }

    // TODO: Get procs PID/Name based on meta data.
    // TODO: Check whitelist.
    ret = nfq_get_payload(tb, &data);
    if (ret >= 0)
    {
        const struct sniff_ip *ip;              /* The IP header */
        const struct sniff_tcp *tcp;            /* The TCP header */
        const char *payload;                    /* Packet payload */

        int size_ip;
        int size_tcp;
        int size_payload;

        ip = (struct sniff_ip*)(data);
        size_ip = IP_HL(ip)*4;
        if (size_ip < 20) {
            printf("[!!] Invalid IP header length: %u bytes\n", size_ip);
            return;
        }

        /* print source and destination IP addresses */
        printf("[>] From: %s\n", inet_ntoa(ip->ip_src));
        printf("[>] To: %s\n", inet_ntoa(ip->ip_dst));

        /* determine protocol */    
        switch(ip->ip_p) {
            case IPPROTO_TCP:
                printf("[>] Protocol: TCP\n");
                break;
            case IPPROTO_UDP:
                printf("[>] Protocol: UDP\n");
                //TODO: handle this better
                curr_entry->ip_src = strdup(inet_ntoa(ip->ip_src));
                curr_entry->ip_dst = strdup(inet_ntoa(ip->ip_dst));
                return id;
            case IPPROTO_ICMP:
                printf("[>] Protocol: ICMP\n");
                return id;
            case IPPROTO_IP:
                printf("[>] Protocol: IP\n");
                return id;
            default:
                printf("[!!] Protocol: unknown\n");
                return id;
        }

        // Check for TCP
        // printf("[#] Protocol: %d\n", data[9]);
        // if( data[9] != 6)
        //     return id; /* TODO: Handle this packet */


        /* define/compute tcp header offset */
        tcp = (struct sniff_tcp*)(data + size_ip);
        size_tcp = TH_OFF(tcp)*4;
        if (size_tcp < 20) {
            printf("[!!] Invalid TCP header length: %u bytes\n", size_tcp);
            return;
        }

        printf("[>] Src port: %d\n", ntohs(tcp->th_sport));
        printf("[>] Dst port: %d\n", ntohs(tcp->th_dport));

        /* define/compute tcp payload (segment) offset */
        payload = (u_char *)(data + size_ip + size_tcp);

        /* compute tcp payload (segment) size */
        size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);

        if (size_payload > 0)
            printf("   Payload (%d bytes):\n", size_payload);

        /* DEBUG */
        // int i = 0;
        // printf("\n[#] Payload [%d]: ", ret);
        // for (i = 0; i < ret; i++) {
        //    printf("%1X", data[i] );
        // }
        //
        //
        curr_entry->ip_src = strdup(inet_ntoa(ip->ip_src));
        curr_entry->ip_dst = strdup(inet_ntoa(ip->ip_dst));
        curr_entry->port = ntohs(tcp->th_dport);
    }

    return id;
}

int check_whitelist(struct laf_entry *entry){

    if (entry->ip_src == NULL || entry->ip_dst == NULL)
    {
        printf("[>] Dropping\n\n");
        return NF_DROP;
    }

    int i; 
    for(i = 0; i < total_entries; i++)
    {
        if(((strcmp(entry->ip_dst, allowed[i].ip_dst) == 0) || (strcmp(allowed[i].ip_dst, "*")==0))
                && (entry->port == allowed[i].port 
                    || allowed[i].port == '*'))
        {
            printf("[>] Accepting\n\n");
            return NF_ACCEPT;
        }
    }

    printf("[>] Dropping\n\n");

    return NF_DROP;

}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
        struct nfq_data *nfa, void *data)
{
    struct laf_entry entry = {};
    u_int32_t id = process_pkt(nfa, &entry);
    int verdict = check_whitelist(&entry);
    return nfq_set_verdict(qh, id, verdict, 0, NULL);
}

// TODO: Check user permissions, signal handling.
int main(int argc, char **argv)
{
    read_whitelist(); 
    print_allowed();
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    struct nfnl_handle *nh;
    int fd;
    int rv;
    char buf[4096] __attribute__ ((aligned));

    printf("opening library handle\n");
    h = nfq_open();
    if (!h) {
        fprintf(stderr, "error during nfq_open()\n");
        exit(1);
    }

    printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
    if (nfq_unbind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_unbind_pf()\n");
        exit(1);
    }

    printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_bind_pf()\n");
        exit(1);
    }

    printf("binding this socket to queue '0'\n");
    qh = nfq_create_queue(h,  0, &cb, NULL);
    if (!qh) {
        fprintf(stderr, "error during nfq_create_queue()\n");
        exit(1);
    }

    printf("setting copy_packet mode\n");
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "can't set packet_copy mode\n");
        exit(1);
    }

    fd = nfq_fd(h);

    while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0) {
       // printf("pkt received\n");
        nfq_handle_packet(h, buf, rv);
    }

    printf("unbinding from queue 0\n");
    nfq_destroy_queue(qh);

#ifdef INSANE
    /* normally, applications SHOULD NOT issue this command, since
     * it detaches other programs/sockets from AF_INET, too ! */
    printf("unbinding from AF_INET\n");
    nfq_unbind_pf(h, AF_INET);
#endif

    printf("closing library handle\n");
    nfq_close(h);

    exit(0);
}


