#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <linux/if_packet.h>

unsigned short csum(void *buffer, unsigned int n)
{
	unsigned short byte;
	short ret;
	register unsigned long sum = 0;
	const uint16_t *buf = buffer;

	while (n > 1) {
		sum += *buf++;
		n -= 2;
	}
	if (n == 1) {
		byte = 0;
		*((u_char*)&byte) = *(u_char*)buf;
		sum += byte;
		sum += htons(*(u_char *)buf << 8);
	}

	sum = (sum >> 16) + (sum & 0xffff);
	sum = sum + (sum >> 16);
	ret = (unsigned short)~sum;

	return ret;
}

int main(int argc, char *argv[])
{
	struct sockaddr_ll saddr, daddr;
	int saddr_size, data_size, bytes_sent;
	struct ethhdr *ehdr;
	struct iphdr *ip;
	struct udphdr *udp;
	unsigned char *payload;
	unsigned char ch;
	unsigned char *buffer;
	int i, j;

	int sock_in = socket(AF_PACKET, SOCK_RAW, IPPROTO_UDP);
	int sock_out = socket(AF_PACKET, SOCK_RAW, IPPROTO_UDP);

	if (argc != 3) {
		printf("usage: %s <in_eth> <out_eth>\n", argv[0]);
		return 1;
	}

	buffer = (unsigned char*)malloc(IP_MAXPACKET * sizeof(unsigned char));

	bzero(buffer, IP_MAXPACKET * sizeof(unsigned char));
	bzero(&saddr, sizeof(struct sockaddr_ll));

	saddr.sll_family = AF_PACKET;
	saddr.sll_protocol = htons(ETH_P_ALL);
	saddr.sll_ifindex = if_nametoindex(argv[1]);
	if (bind(sock_in, (struct sockaddr *)&saddr, sizeof(saddr)) < 0) {
		perror("bind failed\n");
		close(sock_in);
	}

	bzero(&daddr, sizeof(struct sockaddr_ll));
	daddr.sll_family = AF_PACKET;
	daddr.sll_protocol = htons(ETH_P_ALL);
	daddr.sll_ifindex = if_nametoindex(argv[2]);
	if (bind(sock_out, (struct sockaddr *)&daddr, sizeof(daddr)) < 0) {
		perror("bind failed\n");
		close(sock_out);
	}
	struct ifreq ifr;
	bzero(&ifr, sizeof(ifr));
	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", argv[2]);
	if (setsockopt(sock_out, SOL_SOCKET, SO_BINDTODEVICE, (void *)&ifr, sizeof(ifr)) < 0) {
		perror("bind to eth1");
	}

	while (1) {
		saddr_size = sizeof(struct sockaddr);
		data_size = recvfrom(sock_in, buffer, ETH_FRAME_LEN, 0, (struct sockaddr *)&saddr, (socklen_t *)&saddr_size);
		if (data_size > ETH_FRAME_LEN)
			data_size = ETH_FRAME_LEN;

		if (data_size < 0) {
			printf("Recvfrom error , failed to get packets\n");
			return 1;
		} else {
			ehdr =  (struct ethhdr *)buffer;
			ip = (struct iphdr *)(ehdr + 1);
			udp = (struct udphdr *)(ip + 1);
			i = 0;
			j = ntohs(udp->len) - sizeof(struct udphdr) - 1;

			printf("Received %d bytes\n", data_size);
			printf("%x:%x:%x:%x:%x:%x -> %x:%x:%x:%x:%x:%x\n",
				ehdr->h_source[0], ehdr->h_source[1], ehdr->h_source[2], ehdr->h_source[3], ehdr->h_source[4], ehdr->h_source[5],
				ehdr->h_dest[0], ehdr->h_dest[1], ehdr->h_dest[2], ehdr->h_dest[3], ehdr->h_dest[4], ehdr->h_dest[5]);

			payload = (unsigned char *)(udp + 1);
			printf("Trying to resend '%s'(%lu, %d) ", payload, ntohs(udp->len) - sizeof(struct udphdr), ntohs(ip->ihl));

			while (i < j) {
				ch = payload[i];
				payload[i] = payload[j];
				payload[j] = ch;
				i++;
				j--;
			}

			udp->check = 0;
			udp->check = csum(udp, sizeof(struct udphdr));
			printf("as '%s'\n", payload);

			bytes_sent = sendto(sock_out, buffer, data_size, 0, (struct sockaddr *)&daddr, sizeof(daddr));
			if (bytes_sent < 0) {
				printf("sendto data_suze = %d\n", data_size+ 0);
				if (errno == EMSGSIZE)
					break;
			}
		}
	}
	free(buffer);
	close(sock_in);
	close(sock_out);

	return 0;
}
