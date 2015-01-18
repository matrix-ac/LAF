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
#include <sys/socket.h>
#include <netdb.h>
#include <linux/types.h>
#include <linux/netfilter.h>            /* for NF_ACCEPT */
#include <arpa/inet.h>                  /* for inet_ntop(), inet_pton() */
#include <string.h>                     /* for memcpy(), strcmp() etc. */
#include <signal.h>
#include <assert.h>

#include <libnetfilter_queue/libnetfilter_queue.h>

#include "main.h"

struct laf_entry allowed[MAX_ALLOWED_WHIETLIST];
int total_entries, stats_pkt_count, stats_pkt_ip, stats_pkt_tcp, stats_pkt_udp, stats_pkt_icmp, stats_pkt_unknown, stats_pkt_blocked, stats_pkt_allowed = 0;
int reload_config = 0;

/* Print all whitelisted entries */
int print_allowed()
{
    int i; 
    for(i = 0; i < total_entries; i++)
    {
        printf("[>] Allowing traffic to %s from %s", allowed[i].ip_dst, allowed[i].binary_name);
        if(allowed[i].port != 0)
        {
            printf(" on port %d", allowed[i].port);
        }
        printf("\n");
    }
    return 0;
}

/* Print a single entry */
int print_entry(struct laf_entry *entry)
{
    printf("'%s'\t", entry->binary_name);
    printf("'%s'\t", entry->ip_src);
    printf("'%s'\t", entry->ip_dst);
    printf("'%d'\n", entry->port);

    return 0;
}

/* Load the whitelist into memory */
int read_whitelist()
{
    FILE *fp;
    char buff[LINE_BUFFER_SIZE];

    fp = fopen("whitelist.txt", "r");

    if( fp == NULL ){
        fprintf(stderr, "[!!] Error opening the white list file (whitelist.txt).\n");
        return 1;
    }

    while (fgets(buff, LINE_BUFFER_SIZE, fp) != NULL)
    {   
        int c = 0;
        char *split_entry;
        struct laf_entry entry;

        split_entry = strtok(buff, " ");

        while(split_entry != NULL)
        {
            switch(c)
            {
                case 0:
                    entry.binary_name = strdup(split_entry);
                    break;
                case 1:
                    entry.ip_dst = strdup(split_entry);
                    break;
                case 2:
                    entry.port = atoi(split_entry);
                    break;
                default:
                    fprintf(stderr, "[!!] Error reading config, too many tokens!");
                    return 2;
            }
            c++;
            split_entry = strtok(NULL, " ");
        }

        allowed[total_entries] = entry;
        total_entries++;
    }

    fclose(fp);

    /* TODO: Should read_whitlist exit the application if it fails to read ? */
    return 0;
}

/* load the config */
int load_config()
{
    int rtn = 1;

    rtn = read_whitelist(); 
    print_allowed();

    return rtn;
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

        /* TODO Find a cleaner way to get the hostname of the IP address. */
        /*
           struct sockaddr_in sa;
           char host[NI_MAXHOST], service[NI_MAXSERV];

           sa.sin_family = AF_INET;
           sa.sin_port = 80; 
           sa.sin_addr = ip->ip_dst;

           getnameinfo(&sa, sizeof sa, host, sizeof host, service, sizeof service, 0);
           printf("[>] To: %s (%s)\n", host, inet_ntoa(ip->ip_dst)); TODO Handle return value. 
           */

        /* print source and destination IP addresses */
        printf("[>] From: %s\n", inet_ntoa(ip->ip_src));
        printf("[>] To: %s\n", inet_ntoa(ip->ip_dst));


        /* determine protocol */    
        switch(ip->ip_p) {
            case IPPROTO_TCP:
                printf("[>] Protocol: TCP\n");
                stats_pkt_tcp++;
                break;
            case IPPROTO_UDP:
                printf("[>] Protocol: UDP\n");
                stats_pkt_udp++;
                /* TODO: handle this better */
                curr_entry->ip_src = strdup(inet_ntoa(ip->ip_src));
                curr_entry->ip_dst = strdup(inet_ntoa(ip->ip_dst));
                break;
            case IPPROTO_ICMP:
                printf("[>] Protocol: ICMP\n");
                stats_pkt_icmp++;
                break;
            case IPPROTO_IP:
                printf("[>] Protocol: IP\n");
                stats_pkt_ip++;
                break;
            default:
                printf("[!!] Protocol: unknown\n");
                stats_pkt_unknown++;
                break;
        }

        /* Do nothing else if it's not TCP. */
        if(ip->ip_p != IPPROTO_TCP){
            stats_pkt_blocked++;
            return id;
        }

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

        const char *new_binary_name = NULL;
        if(binary_name != NULL){
            new_binary_name = get_actual_binary_name(binary_name);
            if (new_binary_name == NULL)
            {
                new_binary_name = binary_name;
            }
            printf("[>] Binary: %s\n", new_binary_name);
        } else {
            new_binary_name = malloc(0);
        }

        curr_entry->binary_name = new_binary_name;
        curr_entry->ip_src = strdup(inet_ntoa(ip->ip_src));
        curr_entry->ip_dst = strdup(inet_ntoa(ip->ip_dst));
        curr_entry->port = ntohs(tcp->th_dport);

        binary_name = NULL;

        /* compute tcp payload (segment) size */
        size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);

        if (size_payload > 0)
            printf("[#] Payload %d bytes.\n", size_payload);

    }

    return id;
}

/* Check if the whitelist contains this entry */
int check_whitelist(struct laf_entry *entry)
{
    int i; 

    if (entry->ip_src == NULL || entry->ip_dst == NULL)
    {
        printf("[>] Dropping\n\n");
        return NF_DROP;
    }

    for(i = 0; i < total_entries; i++)
    {
        if(((strcmp(entry->binary_name, allowed[i].binary_name) == 0) || (strcmp(allowed[i].binary_name, "*") == 0))
                && ((strcmp(entry->ip_dst, allowed[i].ip_dst) == 0) || (strcmp(allowed[i].ip_dst, "*")==0))
                && (entry->port == allowed[i].port 
                    || allowed[i].port == atoi("*")))
        {
            printf("[>] Accepting\n\n");
            stats_pkt_allowed++;
            return NF_ACCEPT;
        }
    }

    printf("[>] Dropping\n\n");
    stats_pkt_blocked++;
    return NF_DROP;
}

/* Callback for the packet */
static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
        struct nfq_data *nfa, void *data)
{
    struct laf_entry entry = {0}; /* Hack to allow -pedantic to compile */
    u_int32_t id = process_pkt(nfa, &entry);
    int verdict = check_whitelist(&entry);
    free((char *) entry.binary_name);
    free(entry.ip_src);
    free(entry.ip_dst);

    stats_pkt_count++;

    data = data; nfmsg = nfmsg; /* Hack to allow -pedantic to compile */
    return nfq_set_verdict(qh, id, verdict, 0, NULL);
}

/* TODO: Remove printf/puts from signal handler. */
static void termination_handler(int signo) {
    switch (signo) 
    {
        case SIGHUP:
            puts("Reloading whitelist.\n");
            reload_config = 1;
            break;
        case SIGINT:
        case SIGTERM:
        default:
            printf("\nPackets total:   %d\n", stats_pkt_count);
            printf("Packets allowed: %d\n", stats_pkt_allowed);
            printf("Packets blocked: %d\n", stats_pkt_blocked);
            printf("IP: %d, TCP: %d, UDP: %d, ICMP: %d, Unknown: %d\n\n", 
                    stats_pkt_ip, stats_pkt_tcp, stats_pkt_udp, stats_pkt_icmp, 
                    stats_pkt_unknown);

            exit(EXIT_SUCCESS);
            break;
    }
}

/* Main entry point to the application */
int main(int argc, char **argv)
{
    int fd, rv;
    struct sigaction new_action, old_action;
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    char buf[MAX_PKT_BUFFER] __attribute__ ((aligned));

    /* Set up the structure to specify the new action. */
    new_action.sa_handler = termination_handler;
    sigemptyset (&new_action.sa_mask);
    new_action.sa_flags = 0;

    sigaction (SIGINT, NULL, &old_action);
    if (old_action.sa_handler != SIG_IGN)
        sigaction (SIGINT, &new_action, NULL);

    sigaction (SIGHUP, NULL, &old_action);
    if (old_action.sa_handler != SIG_IGN)
        sigaction (SIGHUP, &new_action, NULL);

    sigaction (SIGTERM, NULL, &old_action);
    if (old_action.sa_handler != SIG_IGN)
        sigaction (SIGTERM, &new_action, NULL);

    if (getuid() > 0) 
    {
        fprintf(stderr, "[!!] This is a simple test to check if you are root, there is a better way to do this but for now this will do.\nBye.\n");
        exit(EXIT_FAILURE);
    }

    if (load_config() > 0)
    {
        fprintf(stderr, "[!!] Exiting - Unable to load config file.\n");
        exit(EXIT_FAILURE);
    }

    printf("[#] Opening library handle.\n");
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

        if(reload_config == 1)
        {
            printf("Reload-Config!\n");
            if (load_config() > 0)
            {
                fprintf(stderr, "[!!] Exiting - Unable to load config file.\n");
                exit(EXIT_FAILURE);
            }
            reload_config = 0;
        }
    }

    printf("[#] Unbinding from queue '0'.\n");
    nfq_destroy_queue(qh);

    printf("[#] Closing library handle.\n");
    nfq_close(h);

    /* TODO Display help options program arguments */
    argc = argc; argv = argv; /* Hack to allow -pedantic to compile */

    exit(0);
}

const char* get_actual_binary_name(const char* path)
{
    char *last_split;
    char *split_path = strdup(path);
    char *non_const_path = strdup(path);
    last_split = strtok(non_const_path, "/");
    while(last_split != NULL)
    {
        last_split = strtok(NULL, "/");
        if(last_split != NULL)
        {
            split_path = strdup(last_split);
        }
    }   

    free(non_const_path);
    return (const char *) split_path;
}
