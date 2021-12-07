#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <libnet.h>
#include <linux/netfilter.h> /* for NF_ACCEPT */
#include <errno.h>

#include <libnetfilter_queue/libnetfilter_queue.h>

struct http_packet
{
    struct libnet_ipv4_hdr ipv4_hdr;
    struct libnet_tcp_hdr tcp_hdr;
    char data[2048];
};

char *block_site;
int len = 0;

int is_block(unsigned char *buf, int size)
{
    struct http_packet packet;
    memcpy(&packet, buf, size);

    for (int i = 0; i < 2042; i++)
    {
        if (!strncmp(packet.data + i, "Host: ", 6))
        {
            if (!strncmp(packet.data + i + 6, block_site, len))
            {
                printf("%s is founded! block! \n", block_site);
                return 1;
            }
        }
    }
    return 0;
}

struct ret_data
{
    u_int32_t id;
    int block;
};

/* returns packet id */
static struct ret_data print_pkt(struct nfq_data *tb)
{
    int id = 0;
    int block;
    struct nfqnl_msg_packet_hdr *ph;
    struct nfqnl_msg_packet_hw *hwph;
    u_int32_t mark, ifi;
    int ret;
    unsigned char *data;

    ph = nfq_get_msg_packet_hdr(tb);
    if (ph)
    {
        id = ntohl(ph->packet_id);
    }

    hwph = nfq_get_packet_hw(tb);
    if (hwph)
    {
        int i, hlen = ntohs(hwph->hw_addrlen);
    }

    mark = nfq_get_nfmark(tb);
    ifi = nfq_get_indev(tb);
    ifi = nfq_get_outdev(tb);
    ifi = nfq_get_physindev(tb);
    ifi = nfq_get_physoutdev(tb);
    ret = nfq_get_payload(tb, &data);
    if (ret >= 0)
    {
        block = is_block(data, ret);
    }

    struct ret_data rd;
    rd.id = id;
    rd.block = block;

    return rd;
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
              struct nfq_data *nfa, void *data)
{
    struct ret_data rd = print_pkt(nfa);
    //printf("entering callback\n");
    if (rd.block)
    {
        return nfq_set_verdict(qh, rd.id, NF_DROP, 0, NULL);
    }
    else
    {
        return nfq_set_verdict(qh, rd.id, NF_ACCEPT, 0, NULL);
    }
}

void usage(void)
{
    puts("syntax : netfilter-test <host>");
    puts("sample : netfilter-test test.gilgil.net");
}

int main(int argc, char **argv)
{
    if (argc != 2)
    {
        usage();
        exit(1);
    }

    len = strlen(argv[1]);
    block_site = (char *)malloc(sizeof(len));
    memcpy(block_site, argv[1], len);

    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    struct nfnl_handle *nh;
    int fd;
    int rv;
    char buf[4096] __attribute__((aligned));

    printf("opening library handle\n");
    h = nfq_open();
    if (!h)
    {
        fprintf(stderr, "error during nfq_open()\n");
        exit(1);
    }

    printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
    if (nfq_unbind_pf(h, AF_INET) < 0)
    {
        fprintf(stderr, "error during nfq_unbind_pf()\n");
        exit(1);
    }

    printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
    if (nfq_bind_pf(h, AF_INET) < 0)
    {
        fprintf(stderr, "error during nfq_bind_pf()\n");
        exit(1);
    }

    printf("binding this socket to queue '0'\n");
    qh = nfq_create_queue(h, 0, &cb, NULL);
    if (!qh)
    {
        fprintf(stderr, "error during nfq_create_queue()\n");
        exit(1);
    }

    printf("setting copy_packet mode\n");
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0)
    {
        fprintf(stderr, "can't set packet_copy mode\n");
        exit(1);
    }

    fd = nfq_fd(h);

    for (;;)
    {
        if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0)
        {
            //printf("pkt received\n");
            nfq_handle_packet(h, buf, rv);
            continue;
        }
        /* if your application is too slow to digest the packets that
		 * are sent from kernel-space, the socket buffer that we use
		 * to enqueue packets may fill up returning ENOBUFS. Depending
		 * on your application, this error may be ignored. nfq_nlmsg_verdict_putPlease, see
		 * the doxygen documentation of this library on how to improve
		 * this situation.
		 */
        if (rv < 0 && errno == ENOBUFS)
        {
            printf("losing packets!\n");
            continue;
        }
        perror("recv failed");
        break;
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

    free(block_site);
    exit(0);
}