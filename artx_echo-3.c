#include <errno.h>
#include <ev.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/un.h>
#include <unistd.h>
#include <pthread.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <net/if.h>
#include <linux/if_packet.h>

#define MAIN_SOCKET "/tmp/main_socket"
#define THREAD_SOCKET "/tmp/thread_socket"
#define IPV4_FRAME_LEN 65535
#define BUF_SZ IPV4_FRAME_LEN

struct client {
	ev_io io;
	int main_fd;
	int sock_in;
	int sock_out;
	struct sockaddr_ll *daddr;
	struct client *next;
	struct client *prev;
};

struct io_args {
	ev_io io;
	int main_fd;
	int sock_in;
	int sock_out;
	struct sockaddr_ll *daddr;
	char *if_in;
	char *if_out;
};

struct client *clients = NULL;

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

int pass_to_main(char *buff)
{
	struct sockaddr_un addr_un;
	socklen_t addrlen = sizeof(struct sockaddr);
	int ret = -1, fd;

	if ((fd = socket(AF_UNIX, SOCK_DGRAM, 0)) < 0) {
		perror("socket");
		goto out;
	}

	bzero(&addr_un, sizeof(addr_un));
	addr_un.sun_family = AF_UNIX;
	strcpy(addr_un.sun_path, THREAD_SOCKET);
	unlink(THREAD_SOCKET);
	if (bind(fd, (struct sockaddr *)&addr_un, sizeof(addr_un)) < 0) {
		perror("bind");
		goto out;
	}

	bzero(&addr_un, sizeof(addr_un));
	addr_un.sun_family = AF_UNIX;
	strcpy(addr_un.sun_path, MAIN_SOCKET);
	if (connect(fd, (struct sockaddr *)&addr_un, sizeof(addr_un)) == -1) {
		perror("connect");
		goto out;
	}

	if (send(fd, buff, strlen(buff) + 1, 0) == -1) {
		perror("send");
	}
	recvfrom(fd, buff, BUF_SZ, 0, (struct sockaddr *)&addr_un, &addrlen);
	close(fd);

	ret = 0;
out:
	return ret;
}

uint16_t csum(void *buffer, unsigned int n)
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

void thread_read_cb(struct ev_loop *loop, struct ev_io *io, int revents)
{
	struct sockaddr_un addr_un;
	struct client *clnt;
//	8 + 65,507 // UDP + payload // 65535
	char buffer[IPV4_FRAME_LEN];
	ssize_t read;
	struct io_args *args;
	int fd;
//	printf("inside of %s\n", __func__);

	if (EV_ERROR & revents) {
		perror("invalid event");
		return;
	}
	args = (struct io_args*)io;

	struct sockaddr_ll saddr, *daddr = args->daddr;
	int saddr_size, data_size, bytes_sent;
	struct ethhdr *ehdr;
	struct iphdr *ip;
	struct udphdr *udp;
	unsigned char *payload;
	unsigned char ch;
	int i, j, uread;
		saddr_size = sizeof(struct sockaddr);
//		printf("%s: args->sock_in = %d\n", __func__, args->sock_in);
		read = recvfrom(args->sock_in, buffer, IPV4_FRAME_LEN, 0, (struct sockaddr *)&saddr, (socklen_t *)&saddr_size);
//		printf("get some data [%ld]\n", read);

//			if (read > ETH_FRAME_LEN)
//				read = ETH_FRAME_LEN;

		if (read < 0) {
			perror("recvfrom");
			printf("Recvfrom error , failed to get packets, errno = %d\n", errno);
			return;
		} else if (read > 0) {
			ehdr =  (struct ethhdr *)buffer;
			ip = (struct iphdr *)(ehdr + 1);
			udp = (struct udphdr *)((char *)ip + (ip->ihl << 2));
			payload = (unsigned char *)(udp + 1);
#if 1
//			printf("ehdr->h_proto = %d, ip->protocol = %d\n", ehdr->h_proto, ip->protocol);

			if (ntohs(ehdr->h_proto) != ETH_P_IP) {
//				printf("h_proto(0x%x) != ETH_P_IP\n", ehdr->h_proto);
				return;
			}
			if (ip->protocol != IPPROTO_UDP) {
//				printf("protocol(0x%x) != IPPROTO_UDP\n", ip->protocol);
				return;
			}
#endif
			uint16_t orig_csum = ntohs(udp->check);
			udp->check = 0;
			udp->check = csum(udp, sizeof(struct udphdr) + udp->len);
#if 0
			if (orig_csum != udp->check) {
				printf("CSUM %x != %x\n", orig_csum, udp->check);
				udp->check = orig_csum;
				printf("BAD CSUM!!!\n");
		//		return;
			} else
				printf("CSUM OK-OK-OK!!!\n");
#endif
//			return;
			i = 0;
			j = ntohs(udp->len) - sizeof(struct udphdr)- 1;

			long int j0 = j;
			ch = payload[j + 1];
			payload[j + 1] = '\0';
			printf("Received %ld bytes: '%s', udp->len = %d\n", read, payload, ntohs(udp->len));
			printf("%x:%x:%x:%x:%x:%x -> %x:%x:%x:%x:%x:%x\n",
				ehdr->h_source[0], ehdr->h_source[1], ehdr->h_source[2], ehdr->h_source[3], ehdr->h_source[4], ehdr->h_source[5],
				ehdr->h_dest[0], ehdr->h_dest[1], ehdr->h_dest[2], ehdr->h_dest[3], ehdr->h_dest[4], ehdr->h_dest[5]);

			printf("Trying to resend '%s'(%lu, %d)\n", payload, ntohs(udp->len) - sizeof(struct udphdr), ntohs(ip->ihl));
			printf("[i, j] = [%d, %d]\n", i, j);
			while (i < j) {
				ch = payload[i];
				payload[i] = payload[j];
				payload[j] = ch;
				i++;
				j--;
			}

			udp->check = 0;
			udp->check = csum(udp, sizeof(struct udphdr) + udp->len);
			printf("as '%s'\n", payload);
			payload[j0 + 1] = ch;

			bytes_sent = sendto(args->sock_out, buffer, read, 0, (struct sockaddr *)daddr, sizeof(struct sockaddr_ll));
			if (bytes_sent < 0) {
				perror("thread sendto");
				return;
			}
			printf("sendto data_size = %ld\n", read+ 0);
		}

	if (read == 0)
		return;
/*
	read = recv(io->fd, buffer, BUF_SZ, 0);

	if (read < 0) {
		perror("read error");
		return;
	}

	if (read == 0) {
		ev_io_stop(loop, io);
		clnt = (struct client*)io;
		if (!clnt->prev) {
			if (clients->next) {
				clients = clnt->next;
				clients->next->prev = NULL;
			} else
				clients = NULL;
		} else if (!clnt->next) {
			clnt->prev->next = NULL;
		} else {
			clnt->prev->next = clnt->next;
			clnt->next->prev = clnt->prev;
		}

		free(clnt);
		return;
	} else {
		buffer[read] = '\0';
		if (!strncmp(buffer, "quit", 4)) {
			bzero(&addr_un, sizeof(addr_un));
			addr_un.sun_family = AF_UNIX;
			strcpy(addr_un.sun_path, MAIN_SOCKET);
			fd = socket(AF_UNIX, SOCK_DGRAM, 0);
			if (bind(fd, (struct sockaddr *)&addr_un, sizeof(addr_un)) < 0) {
				perror("bind");
			}
			if (sendto(fd, "\0", 1, 0, (struct sockaddr *)&addr_un, sizeof(addr_un)) == -1) {
				perror("thread send");
			}
			ev_io_stop(loop, io);
			ev_break(loop, EVBREAK_ONE);
			ev_loop_destroy(loop);
			free_clients();
			return;
		}
	}
*/
	printf("pass_to_main()...\n");
	pass_to_main(buffer);
	printf("send(read == %ld)...\n", read);
	send(io->fd, buffer, read, 0);
	bzero(buffer, read);
	printf("after send()...\n");
}
/*
void thread_accept_cb(struct ev_loop *loop, struct ev_io *io, int revents)
{
	struct sockaddr_in client_addr;
	struct client *client;
	socklen_t client_len;
	int fd;

	printf("%s\n", __func__);
	client_len = sizeof(client_addr);
	client = (struct client*)malloc(sizeof(struct client));
	if (!client) {
		perror("malloc");
		return;
	}

	client->prev = client->next = NULL;

	if (EV_ERROR & revents) {
		perror("invalid event");
		free(client);
		return;
	}

	fd = accept(io->fd, (struct sockaddr *)&client_addr, &client_len);

	if (fd < 0) {
		perror("accept");
		free(client);
		return;
	}

	ev_io_init(&(client->io), thread_read_cb, fd, EV_READ);
	ev_io_start(loop, &(client->io));
	add_client(client);
}
*/
void* thread_main(void *arg)
{
	struct ev_loop *loop;
	struct client clnt;
	struct io_args *args;
	struct sockaddr_in addr;
	int opt = 1;

	struct sockaddr_ll saddr, daddr;
	int saddr_size, data_size, bytes_sent;
	struct ethhdr *ehdr;
	struct iphdr *ip;
	struct udphdr *udp;
	struct ifreq ifr;
	unsigned char *payload;
	unsigned char ch;
	unsigned char *buffer;
	int i, j;

	args = (struct io_args *)arg;
	args->sock_in = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW);
	if (args->sock_in == -1) {
		perror("socket");
		return NULL;
	}
	args->sock_out = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW);
	if (args->sock_out == -1) {
		perror("socket");
		return NULL;
	}
	loop = ev_loop_new(0);

	buffer = (unsigned char*)malloc(IP_MAXPACKET * sizeof(unsigned char));

	bzero(buffer, IP_MAXPACKET * sizeof(unsigned char));

	bzero(&saddr, sizeof(struct sockaddr_ll));
	saddr.sll_family = AF_PACKET;
	saddr.sll_protocol = htons(ETH_P_ALL);
	saddr.sll_ifindex = if_nametoindex(args->if_in);
	printf("args->sock_in = %d\n", args->sock_in);
	if (bind(args->sock_in, (struct sockaddr *)&saddr, sizeof(saddr)) < 0) {
		perror("bind failed");
		close(args->sock_in);
		free(buffer);
		return NULL;
	}

	bzero(&daddr, sizeof(struct sockaddr_ll));
	daddr.sll_family = AF_PACKET;
	daddr.sll_protocol = htons(ETH_P_ALL);
	daddr.sll_ifindex = if_nametoindex(args->if_out);
	printf("binding sock_out(%d) on %s(%d)\n", args->sock_out, args->if_out, daddr.sll_ifindex );
	if (bind(args->sock_out, (struct sockaddr *)&daddr, sizeof(daddr)) < 0) {
		perror("bind failed\n");
		close(args->sock_out);
		free(buffer);
		return NULL;
	}

	bzero(&ifr, sizeof(ifr));
	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", args->if_in);
	if (setsockopt(args->sock_in, SOL_SOCKET, SO_BINDTODEVICE, (void *)&ifr, sizeof(ifr)) < 0) {
		perror("bind to eth1");
		free(buffer);
		return NULL;
	}

	if (setsockopt(args->sock_in, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) == -1) {
		perror("setsockopt on sock_in");
		free(buffer);
		return NULL;
	}
	bzero(&ifr, sizeof(ifr));
	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", args->if_out);
	if (setsockopt(args->sock_out, SOL_SOCKET, SO_BINDTODEVICE, (void *)&ifr, sizeof(ifr)) < 0) {
		perror("bind to eth1");
		free(buffer);
		return NULL;
	}

	if (setsockopt(args->sock_out, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) == -1) {
		perror("setsockopt on sock_out");
		free(buffer);
		return NULL;
	}

	printf("INSIDE THREAD\n");

//	while (1) {
//	}
/*
	if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		perror("socket");
		return NULL;
	}

	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) == -1) {
		perror("setsockopt");
	}

	args = (struct io_args *)arg;
	clnt.main_fd = args->main_fd;
	bzero(&addr, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(args->port);
	addr.sin_addr.s_addr = INADDR_ANY;

	if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
		perror("bind");
	}

	if (listen(sock, 2) < 0) {
		perror("listen");
		return NULL;
	}
*/

	printf("args->sock_in = %d\n", args->sock_in);
	clnt.main_fd = args->main_fd;
	clnt.sock_in = args->sock_in;
	clnt.sock_out = args->sock_out;
	clnt.daddr = &daddr;
	ev_io_init(&clnt.io, thread_read_cb, args->sock_in, EV_READ | EV_WRITE);
	ev_io_start(loop, &clnt.io);

	ev_loop(loop, 0);

	unlink(THREAD_SOCKET);

	return  NULL;
}

void read_cb(struct ev_loop* loop, __attribute__ ((unused)) struct ev_io* io, int revents)
{
	struct sockaddr_un addr, th_addr;
	socklen_t sock_len = sizeof(th_addr);
	char buffer[BUF_SZ], ch;
	int i, j, fd, ret, len;
printf("inside of %s\n", __func__);

	if (EV_ERROR & revents) {
		perror("invalid event");
		return;
	}

	if ((fd = socket(AF_UNIX, SOCK_DGRAM, 0)) < 0) {
		perror("socket");
		goto out;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strcpy(addr.sun_path, MAIN_SOCKET);
	unlink(MAIN_SOCKET);
	if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		perror("bind");
		goto out;
	}
	while ((len = recvfrom(fd, buffer, BUF_SZ, 0, (struct sockaddr *)&th_addr, &sock_len)) > 0 &&
			(buffer[0] != '\0')) {

		i = 0;
		j = strlen(buffer) - 1;
		if (j < 0)
			return;

		if (buffer[j] == '\n')
			j--;
		while (i < j) {
			ch = buffer[i];
			buffer[i] = buffer[j];
			buffer[j] = ch;
			i++;
			j--;
		}

		if (strlen(buffer) == 0)
			continue;

		ret = sendto(fd, buffer, strlen(buffer) + 1, 0, (struct sockaddr *)&th_addr, sock_len);
		if (ret < 0) {
			perror("main sendto");
			break;
		}
	}

out:
	if (fd >= 0) {
		close(fd);
	}
	printf("%s: EV_BREAK\n", __func__);
	ev_break(loop, EVBREAK_ONE);
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

	io_args->main_fd = sock;
	io_args->if_in = argv[1];
	io_args->if_out = argv[2];

	ev_io_init(&io_args->io, read_cb, sock, EV_READ | EV_WRITE);
	pthread_create(&thread, NULL, &thread_main, io_args);
	ev_io_start(loop, &io_args->io);
	ev_loop(loop, 0);
sleep(5);
out:
	pthread_join(thread, NULL);
	ev_loop_destroy(loop);
	free(io_args);
	unlink(MAIN_SOCKET);

	return 0;
}

