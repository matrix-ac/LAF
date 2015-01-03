
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>            /* for NF_ACCEPT */
#include <arpa/inet.h>                  /* for inet_ntop(), inet_pton() */
#include <string.h>                     /* for memcpy() */

#include <libnetfilter_queue/libnetfilter_queue.h>

/* returns packet id */
static u_int32_t print_pkt (struct nfq_data *tb)
{
        int id = 0;
        struct nfqnl_msg_packet_hdr *ph;
        int ret;
        unsigned char *data;

        ph = nfq_get_msg_packet_hdr(tb);
        if (ph) {
                id = ntohl(ph->packet_id);
                printf("hw_protocol=0x%04x hook=%u id=%u ",
                        ntohs(ph->hw_protocol), ph->hook, id);
        }

        // TODO: Get src/dst IP src/dest TCP port.
        // TODO: Get procs PID/Name based on meta data.
        // TODO: Check whitelist.
        ret = nfq_get_payload(tb, &data);
        if (ret >= 0)
        {
            // Get Source IP
            unsigned long raw_src_ip[4];
            char src_ip[INET_ADDRSTRLEN];

            memcpy(raw_src_ip, &data[12], 4);
            inet_ntop(AF_INET, raw_src_ip, src_ip, INET_ADDRSTRLEN);

            printf("[>] SRC IP: %s\n", src_ip);

            // Get Destination IP
            unsigned long raw_dst_ip[4];
            char dst_ip[INET_ADDRSTRLEN];

            memcpy(raw_dst_ip, &data[16], 4);
            inet_ntop(AF_INET, raw_dst_ip, dst_ip, INET_ADDRSTRLEN);

            printf("[>] DST IP: %s\n", dst_ip);

            /* DEBUG */
            int i = 0;
            printf("\n[#] Payload [%d]: ", ret);
            for (i = 0; i < ret; i++) {
               printf("%1X", data[i] );
            }
        }

        fputc('\n', stdout);

        return id;
}
        

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
              struct nfq_data *nfa, void *data)
{
        u_int32_t id = print_pkt(nfa);
        printf("entering callback\n");
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

// TODO: Check user permissions, signal handling.
int main(int argc, char **argv)
{
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
                printf("pkt received\n");
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
