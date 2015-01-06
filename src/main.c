#include "main.h"

struct laf_entry allowed[MAX_ALLOWED_WHIETLIST];
int total_entries = 0;

/* Print all whitelisted entries */
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

/* Print a single entry */
int print_entry(struct laf_entry *entry)
{
    printf("'%s'\t", entry->ip_src);
    printf("'%s'\t", entry->ip_dst);
    printf("'%d'\n", entry->port);

    return 0;
}

/* Load the whitelist into memory */
int read_whitelist()
{
    int line_buff_size = LINE_BUFFER_SIZE;
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

/* Process packet form the queue */
static u_int32_t process_pkt (struct nfq_data *tb, struct laf_entry *curr_entry)
{
    int id = 0;
    struct nfqnl_msg_packet_hdr *ph;
    int ret;
    unsigned char *data;

    ph = nfq_get_msg_packet_hdr(tb);
    if (ph) {
        id = ntohl(ph->packet_id);
        printf("[#] hw_protocol=0x%04x hook=%u id=%u \n",
                ntohs(ph->hw_protocol), ph->hook, id);
    }

    ret = nfq_get_payload(tb, &data);
    if (ret >= 0)
    {
        const struct sniff_ip *ip;              /* The IP header */
        const struct sniff_tcp *tcp;            /* The TCP header */
        const char *payload;                    /* Packet payload */
        const char *binary_name = NULL;

        int size_ip;
        int size_tcp;
        int size_payload;

        ip = (struct sniff_ip*)(data);
        size_ip = IP_HL(ip)*4;
        if (size_ip < 20) {
            printf("[!!] Invalid IP header length: %u bytes\n", size_ip);
            return id;
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

        // Do nothing else if it's not TCP.
        if(ip->ip_p != IPPROTO_TCP)
            return id;

        /* define/compute tcp header offset */
        tcp = (struct sniff_tcp*)(data + size_ip);
        size_tcp = TH_OFF(tcp)*4;
        if (size_tcp < 20) {
            printf("[!!] Invalid TCP header length: %u bytes\n", size_tcp);
            return id;
        }

        printf("[>] Src port: %d\n", ntohs(tcp->th_sport));
        printf("[>] Dst port: %d\n", ntohs(tcp->th_dport));

        binary_name = net_to_pid_name(
            strdup(inet_ntoa(ip->ip_src)),
            ntohs(tcp->th_sport),
            strdup(inet_ntoa(ip->ip_dst)),
            ntohs(tcp->th_dport)
        );

        if(binary_name != NULL)
            printf("[>] Binary: %s\n", binary_name);

        binary_name = NULL;

        /* compute tcp payload (segment) size */
        size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);

        if (size_payload > 0)
            printf("[#] Payload %d bytes.\n", size_payload);

        curr_entry->ip_src = strdup(inet_ntoa(ip->ip_src));
        curr_entry->ip_dst = strdup(inet_ntoa(ip->ip_dst));
        curr_entry->port = ntohs(tcp->th_dport);
    }

    return id;
}

/* Check if the whitelist contains this entry */
int check_whitelist(struct laf_entry *entry)
{
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

/* Callback for the packet */
static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
        struct nfq_data *nfa, void *data)
{
    struct laf_entry entry = {};
    u_int32_t id = process_pkt(nfa, &entry);
    int verdict = check_whitelist(&entry);
    free(entry.ip_src);
    free(entry.ip_dst);
    return nfq_set_verdict(qh, id, verdict, 0, NULL);
}

// TODO: Signal handling.
/* Main entry point to the application */
int main(int argc, char **argv)
{
	uid_t uid=getuid();
	if (uid>0) {
		printf("This is a simple test to check if you are root, there is a better way to do this but for now this will do.\nBye.\n");
		exit(EXIT_FAILURE);
	}

    read_whitelist(); 
    print_allowed();

    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    struct nfnl_handle *nh;
    int fd;
    int rv;
    char buf[MAX_PKT_BUFFER] __attribute__ ((aligned));

    printf("opening library handle\n");
    h = nfq_open();
    if (!h) {
        fprintf(stderr, "[!!] Error during nfq_open().\n");
        exit(1);
    }

    printf("[#] Unbinding existing nf_queue handler for AF_INET (if any).\n");
    if (nfq_unbind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "[!!] Error during nfq_unbind_pf().\n");
        exit(1);
    }

    printf("[#] Binding nfnetlink_queue as nf_queue handler for AF_INET.\n");
    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "[!!] Error during nfq_bind_pf().\n");
        exit(1);
    }

    printf("[#] Binding this socket to queue '0'.\n");
    qh = nfq_create_queue(h,  0, &cb, NULL);
    if (!qh) {
        fprintf(stderr, "[!!] Error during nfq_create_queue().\n");
        exit(1);
    }

    printf("[#] Setting copy_packet mode.\n");
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "[!!] Can't set packet_copy mode.\n");
        exit(1);
    }

    fd = nfq_fd(h);

    while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0) {
        nfq_handle_packet(h, buf, rv);
    }

    printf("[#] Unbinding from queue '0'.\n");
    nfq_destroy_queue(qh);

    printf("[#] Closing library handle.\n");
    nfq_close(h);

    exit(0);
}


