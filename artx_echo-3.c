#include <errno.h>
#include <ev.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/un.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <ctype.h>

#define MAIN_SOCKET "/tmp/main_socket"
#define THREAD_SOCKET "/tmp/thread_socket"
#define IPV4_FRAME_LEN 65535

struct client {
	ev_io io;
	int main_fd;
	int sock_in;
	int sock_out;
	struct sockaddr_ll *saddr, *daddr;
	struct ifreq *ifr_in, *ifr_out;
	struct client *next;
	struct client *prev;
};

struct io_args {
	ev_io io;
	int main_fd;
	int sock_in;
	int sock_out;
	struct sockaddr_ll *saddr;
	struct sockaddr_ll *daddr;
	char *if_in;
	char *if_out;
	struct ev_loop *loop;
};

struct pheader {
	u_int32_t src_addr;
	u_int32_t dst_addr;
	u_int8_t pad;
	u_int8_t proto;
	u_int16_t pkt_length;
};

struct client *clients = NULL;
int done = 0;

char *sane(char *str)
{
	static char static_buf[IPV4_FRAME_LEN];
	int i = 0;

	do {
		static_buf[i] = isprint(str[i]) ? str[i] : '.';
		i++;
	} while (i < IPV4_FRAME_LEN + 1 && str[i]);

	return static_buf;
}

void free_clients()
{
	struct client *client = clients, *tmp;

	while (client) {
		tmp = client;
		client = client->next;
		free(tmp);
	}

	clients = NULL;
}

void add_client(struct client *client)
{
	if (clients == NULL) {
		clients = client;
		clients->next = clients->prev = NULL;
		return;
	}

	client->next = clients;
	clients->prev = client;
	client->prev = NULL;
	clients = client;
}

int pass_to_main(struct ev_io *io, char *buff)
{
	socklen_t addrlen = sizeof(struct sockaddr);
	struct sockaddr_un addr_un;
	int ret = -1, fd;

	memset(&addr_un, 0, sizeof(struct sockaddr_un));
	if ((fd = socket(AF_UNIX, SOCK_DGRAM, 0)) < 0) {
		perror("socket");
		goto out;
	}

	bzero(&addr_un, sizeof(struct sockaddr_un));
	addr_un.sun_family = AF_UNIX;
	strcpy(addr_un.sun_path, THREAD_SOCKET);
	unlink(THREAD_SOCKET);
	if (bind(fd, (struct sockaddr *)&addr_un, sizeof(addr_un)) < 0) {
		perror("bind");
		goto err;
	}

	bzero(&addr_un, sizeof(addr_un));
	addr_un.sun_family = AF_UNIX;
	strcpy(addr_un.sun_path, MAIN_SOCKET);
	if (connect(fd, (struct sockaddr *)&addr_un, sizeof(addr_un)) == -1) {
		perror("connect");
		goto err;
	}

	if (send(fd, buff, IPV4_FRAME_LEN, 0) == -1) {
		perror("send");
		goto err;
	}
	if (strcmp(buff, "quit\n")) {
		if (recvfrom(fd, buff, IPV4_FRAME_LEN, 0, (struct sockaddr *)&addr_un, &addrlen) == -1)
			goto err;
	} else
		done = 1;
	printf("BUFF == '%s'\n", sane(buff + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr)));

	ret = 0;
	goto out;
err:
	close(fd);
out:
	return ret;
}

uint16_t csum(void *buffer, unsigned int n)
{
	register unsigned long sum = 0;
	void *orig_buf = NULL;
	unsigned short byte;
	const uint16_t *buf;
	short ret;

	if (n & 1) {
		orig_buf = buffer;
		buffer = malloc(n + 1);
		memcpy(buffer, orig_buf, n);
		((char *)buffer)[n] = '\0';
		n++;
	}
	buf = buffer;

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

	if (orig_buf)
		free(buffer);

	return ret;
}

void thread_read_cb(struct ev_loop *loop, struct ev_io *io, int revents)
{
	struct io_args *args = (struct io_args*)io;
	struct client *clnt = (struct client *)io;
	struct sockaddr_ll *saddr = args->saddr;
	struct sockaddr_ll *daddr = args->daddr;
	char buffer[IPV4_FRAME_LEN], *pseudo;
	struct ethhdr *ehdr;
	struct udphdr *udp;
	char *payload, ch;
	struct pheader ph;
	struct iphdr *ip;
	int saddr_size;
	ssize_t read;
	int j;

	if (EV_ERROR & revents) {
		perror("invalid event");
		return;
	}

	saddr_size = sizeof(struct sockaddr_ll);
	read = recvfrom(args->sock_in, buffer, IPV4_FRAME_LEN, 0, (struct sockaddr *)&saddr, (socklen_t *)&saddr_size);
	if (read < 0) {
		perror("recvfrom");
		printf("Recvfrom error , failed to get packets, errno = %d\n", errno);
		return;
	} else if (read > 0) {
		ehdr =  (struct ethhdr *)buffer;
		ip = (struct iphdr *)(ehdr + 1);
		udp = (struct udphdr *)((char *)ip + (ip->ihl << 2));
		payload = (char *)(udp + 1);

		if (ntohs(ehdr->h_proto) != ETH_P_IP) {
//			printf("h_proto(0x%x) != ETH_P_IP\n", ntohs(ehdr->h_proto));
			return;
		}
		if (ip->protocol != IPPROTO_UDP) {
//			printf("protocol(0x%x) != IPPROTO_UDP\n", ip->protocol);
			return;
		}

		printf("%s ->",inet_ntoa(*((struct in_addr*)&ip->saddr)));
		printf(" %s\n",inet_ntoa(*((struct in_addr*)&ip->daddr)));

		j = ntohs(udp->len) - sizeof(struct udphdr);

		long int j0 = j;
		ch = payload[j + 1];
		payload[j + 1] = '\0';
		printf("Received %ld bytes: '%s', udp->len = %d\n", read, sane(payload), ntohs(udp->len));
		printf("%x:%x:%x:%x:%x:%x -> %x:%x:%x:%x:%x:%x\n",
			ehdr->h_source[0], ehdr->h_source[1], ehdr->h_source[2], ehdr->h_source[3], ehdr->h_source[4], ehdr->h_source[5],
			ehdr->h_dest[0], ehdr->h_dest[1], ehdr->h_dest[2], ehdr->h_dest[3], ehdr->h_dest[4], ehdr->h_dest[5]);

		if (!strncasecmp("quit", (const char *)payload, 4) && (ntohs(udp->len) == 13)) {
			printf("QUIT\n");
			pass_to_main(io, payload);
			ev_io_stop(loop, io);
			ev_break(loop, EVBREAK_ALL);
			ev_loop_destroy(loop);
			ev_io_stop(args->loop, &args->io);
			return;
		}

//		printf("Trying to resend '%s'(%lu, %d)\n", sane(payload), ntohs(udp->len) - sizeof(struct udphdr), ntohs(ip->ihl));
		payload[j0 + 1] = ch;
	}

	if (read == 0)
		return;

	struct in_addr src, dst;
	src.s_addr = ip->saddr;
	dst.s_addr = ip->daddr;
	printf("ip->saddr = %s, ", inet_ntoa(src));
	printf("ip->daddr = %s\n", inet_ntoa(dst));

	printf("clnt->ifr_in->ifr_name = '%s', clnt->ifr_out->ifr_name = %s\n", clnt->ifr_in->ifr_name, clnt->ifr_out->ifr_name);

	pass_to_main(io, buffer);

	ip->protocol = IPPROTO_UDP;
	ip->saddr = ((struct sockaddr_in *)&clnt->ifr_out->ifr_addr)->sin_addr.s_addr;
	ip->check = 0;
	ip->tot_len = htons(sizeof(struct iphdr) + ntohs(udp->len));
	ip->check = csum((unsigned short *)ip, sizeof(struct iphdr));

	ph.src_addr = ((struct sockaddr_in *)&clnt->ifr_out->ifr_addr)->sin_addr.s_addr;
	ph.dst_addr = ip->daddr;
	ph.pad = 0;
	ph.proto = IPPROTO_UDP;
	ph.pkt_length = udp->len;

	int psize = sizeof(struct pheader) + ntohs(udp->len);
	pseudo = (char*)malloc(psize);

	udp->check = 0;
	memcpy(pseudo, (char *)&ph, sizeof(struct pheader));
	memcpy(pseudo + sizeof(struct pheader), udp, ntohs(udp->len));

	udp->check = csum((unsigned short *)pseudo, psize);
	if (udp->check == 0)
		udp->check = 0xffff;

	sendto(args->sock_out, buffer, read, 0, (struct sockaddr *)daddr, sizeof(struct sockaddr_ll));
	send(io->fd, buffer, read, 0);
	bzero(buffer, read);
	free(pseudo);
}

void* thread_main(void *arg)
{
	struct sockaddr_ll saddr, daddr;
	struct ifreq ifr_in, ifr_out;
	unsigned char *buffer;
	struct ev_loop *loop;
	struct io_args *args;
	struct client clnt;
	int opt = 1;

	printf("INSIDE THREAD\n");
	args = (struct io_args *)arg;
	args->sock_in = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (args->sock_in == -1) {
		perror("socket");
		goto out;
	}
	args->sock_out = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (args->sock_out == -1) {
		perror("socket");
		goto err_socket;
	}
	loop = ev_loop_new(0);

	buffer = (unsigned char*)malloc(IP_MAXPACKET * sizeof(unsigned char));
	if (!buffer) {
		perror("malloc");
		goto err_malloc;
	}

	bzero(buffer, IP_MAXPACKET * sizeof(unsigned char));

	bzero(&saddr, sizeof(struct sockaddr_ll));
	saddr.sll_family = AF_PACKET;
	saddr.sll_protocol = htons(ETH_P_ALL);
	saddr.sll_ifindex = if_nametoindex(args->if_in);
	printf("args->sock_in = %d\n", args->sock_in);

	if (bind(args->sock_in, (struct sockaddr *)&saddr, sizeof(saddr)) < 0) {
		perror("bind failed");
		goto err_bind;
	}

	bzero(&daddr, sizeof(struct sockaddr_ll));
	daddr.sll_family = AF_PACKET;
	daddr.sll_protocol = htons(ETH_P_ALL);
	daddr.sll_ifindex = if_nametoindex(args->if_out);
	printf("binding sock_out(%d) on %s(%d)\n", args->sock_out, args->if_out, daddr.sll_ifindex );
	if (bind(args->sock_out, (struct sockaddr *)&daddr, sizeof(daddr)) < 0) {
		perror("bind failed\n");
		goto err_bind;
	}

	bzero(&ifr_in, sizeof(ifr_in));
	snprintf(ifr_in.ifr_name, sizeof(ifr_in.ifr_name), "%s", args->if_in);
	if (ioctl(args->sock_in, SIOCGIFADDR, &ifr_in) == -1) {
		perror("ioctl");
		goto err_bind;
	}
	if (setsockopt(args->sock_in, SOL_SOCKET, SO_BINDTODEVICE, (void *)&ifr_in, sizeof(ifr_in)) < 0) {
		perror("setsockopt");
		goto err_bind;
	}
	ioctl(args->sock_in, SIOCGIFFLAGS, &ifr_in);
	ifr_in.ifr_flags |= IFF_PROMISC;
	if (ioctl(args->sock_in, SIOCSIFFLAGS, &ifr_in)) {
		perror("ioctl");
		goto err_bind;
	}

	ioctl(args->sock_out, SIOCGIFFLAGS, &ifr_in);
	printf("ift_in = %x, IFF_PROMISC = %d\n", ifr_in.ifr_flags, !!(IFF_PROMISC & ifr_in.ifr_flags));

	printf("sock_in on %s\n", inet_ntoa(((struct sockaddr_in *)&ifr_in.ifr_addr)->sin_addr));

	if (setsockopt(args->sock_in, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) == -1) {
		perror("setsockopt on sock_in");
		goto err_bind;
	}

	bzero(&ifr_out, sizeof(ifr_out));
	snprintf(ifr_out.ifr_name, sizeof(ifr_out.ifr_name), "%s", args->if_out);
	ifr_out.ifr_addr.sa_family = AF_INET;
	if (ioctl(args->sock_out, SIOCGIFADDR, &ifr_out) == -1) {
		perror("ioctl");
		goto err_bind;
	}
	if (setsockopt(args->sock_out, SOL_SOCKET, SO_BINDTODEVICE, (void *)&ifr_out, sizeof(ifr_out)) < 0) {
		perror("setsockopt");
		goto err_bind;
	}

	if (setsockopt(args->sock_out, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) == -1) {
		perror("setsockopt on sock_out");
		goto err_bind;
	}
	ioctl(args->sock_out, SIOCGIFFLAGS, &ifr_out);
	ifr_out.ifr_flags |= IFF_PROMISC;
	if (ioctl(args->sock_out, SIOCSIFFLAGS, &ifr_out)) {
		perror("ioctl");
		goto err_bind;
	}
	printf("sock_out on %s\n", inet_ntoa(((struct sockaddr_in *)&ifr_out.ifr_addr)->sin_addr));

	printf("args->sock_in = %d\n", args->sock_in);
	clnt.main_fd = args->main_fd;
	clnt.sock_in = args->sock_in;
	clnt.sock_out = args->sock_out;
	clnt.saddr = &saddr;
	clnt.daddr = &daddr;
	clnt.ifr_in = &ifr_in;
	clnt.ifr_out = &ifr_out;

	ev_io_init(&clnt.io, thread_read_cb, args->sock_in, EV_READ | EV_WRITE);
	ev_io_start(loop, &clnt.io);

	ev_loop(loop, 0);

	printf("THREAD FINISHED\n");
	done = 1;
	free(buffer);

	goto out;
err_bind:
	free(buffer);
err_malloc:
	close(args->sock_out);
err_socket:
	close(args->sock_in);
out:
	return  NULL;
}

void read_cb(struct ev_loop* loop, __attribute__ ((unused)) struct ev_io* io, int revents)
{
	struct sockaddr_un addr, th_addr;
	struct ethhdr *ehdr;
	struct iphdr *ip;
	struct udphdr *udp;
	socklen_t sock_len = sizeof(th_addr);
	char buffer[IPV4_FRAME_LEN], ch, *payload;
	int i, j, fd, ret;
//printf("inside of %s\n", __func__);

	if (EV_ERROR & revents) {
		perror("invalid event");
		return;
	}

	if ((fd = socket(AF_UNIX, SOCK_RAW, 0)) < 0) {
		perror("socket");
		goto out;
	}

	memset(&addr, 0, sizeof(addr));
	memset(&th_addr, 0, sizeof(th_addr));
	addr.sun_family = AF_UNIX;
	strcpy(addr.sun_path, MAIN_SOCKET);
	unlink(MAIN_SOCKET);
	if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		perror("bind");
		goto bind_err;
	}

//	len = recv(fd, buffer, IPV4_FRAME_LEN, 0);
	if (recvfrom(fd, buffer, IPV4_FRAME_LEN, 0, (struct sockaddr *)&addr, &sock_len) == -1) {
		perror("recvfrom");
		goto bind_err;
	}

//printf("%s got something, len = %d\n", __func__, len);
	ehdr =  (struct ethhdr *)buffer;
	ip = (struct iphdr *)(ehdr + 1);
	udp = (struct udphdr *)((char *)ip + (ip->ihl << 2));
	payload = (char *)(udp + 1);
	i = 0;
	j = ntohs(udp->len) - sizeof(struct udphdr) - 1;

	ch = payload[j + 1];
	payload[j + 1] = '\0';
//	i = 0;
//	j = strlen(payload) - 1;
	if (j < 0) {
		printf("ntohs(udp->len=%d) - sizeof(struct udphdr) == %d\n", udp->len, j);
		goto bind_err;
	}

//printf("%s: buffer = '%s', udp->len = %d\n", __func__, payload, ntohs(udp->len));
//	if (payload[j] == '\n')
//		j--;
//	j = strlen(payload) - 1;
	while (i < j) {
		ch = payload[i];
		payload[i] = payload[j];
		payload[j] = ch;
		i++;
		j--;
	}
//printf("%s: buffer = '%s'\n", __func__, payload);
	payload[j + 1] = ch;
	if (!done) {
		ret = sendto(fd, buffer, IPV4_FRAME_LEN, 0, (struct sockaddr *)&addr, sock_len);
		if (ret < 0) {
			perror("main sendto");
			goto bind_err;
		}
	}
	goto out;
bind_err:
	close(fd);
out:
	if (done) {
		ev_break(loop, EVBREAK_ONE);
		unlink(THREAD_SOCKET);
	}
}

int main(int argc, char **argv)
{
	struct ev_loop *loop;
	struct sockaddr_un addr;
	struct io_args *io_args;
	pthread_t thread = -1;
	int sock;
	int opt = 1;

	if (argc != 3)
		return -1;

	if ((sock = socket(AF_UNIX, SOCK_DGRAM, 0)) < 0) {
		perror("socket");
		return -1;
	}

	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) == -1) {
		perror("setsockopt");
	}

	loop = EV_DEFAULT;
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_LOCAL;
	strcpy(addr.sun_path, MAIN_SOCKET);
	unlink(MAIN_SOCKET);
	if (bind(sock, (struct sockaddr*)(&addr), sizeof(addr)) < 0) {
		perror("bind");
		return -1;
	}

	listen(sock, 10);

	io_args = malloc(sizeof(struct io_args));
	if (!io_args) {
		perror("malloc");
		goto out;
	}
	bzero(io_args, sizeof(struct io_args));
	io_args->loop = loop;
	io_args->main_fd = sock;
	io_args->if_in = argv[1];
	io_args->if_out = argv[2];

	ev_io_init(&io_args->io, read_cb, sock, EV_READ | EV_WRITE);
	pthread_create(&thread, NULL, &thread_main, io_args);
	ev_io_start(loop, &io_args->io);

	ev_loop(loop, 0);

out:
	pthread_join(thread, NULL);
	ev_loop_destroy(loop);
	free(io_args);
	unlink(MAIN_SOCKET);

	return 0;
}

