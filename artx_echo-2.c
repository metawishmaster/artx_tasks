#include <ev.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/un.h>
#include <unistd.h>
#include <pthread.h>
#include <netinet/in.h>

#define MAIN_SOCKET "/tmp/main_socket"
#define THREAD_SOCKET "/tmp/thread_socket"
#define BUF_SZ 1024

struct client {
	ev_io io;
	int main_fd;
	struct client *next;
	struct client *prev;
};

struct io_args {
	ev_io io;
	int main_fd;
	int port;
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

	ret = 0;
out:
	return ret;
}

void thread_read_cb(struct ev_loop *loop, struct ev_io *io, int revents)
{
	struct sockaddr_un addr_un;
	struct client *clnt;
	char buffer[BUF_SZ];
	ssize_t read;
	int fd;

	if (EV_ERROR & revents) {
		perror("invalid event");
		return;
	}

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

	pass_to_main(buffer);
	send(io->fd, buffer, read, 0);
	bzero(buffer, read);
}

void thread_accept_cb(struct ev_loop *loop, struct ev_io *io, int revents)
{
	struct sockaddr_in client_addr;
	struct client *client;
	socklen_t client_len;
	int fd;

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

void* thread_main(void *arg)
{
	struct ev_loop *loop;
	struct client clnt;
	struct io_args *args;
	struct sockaddr_in addr;
	int sock, opt = 1;

	loop = ev_loop_new(0);

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

	ev_io_init(&clnt.io, thread_accept_cb, sock, EV_READ | EV_WRITE);
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
		if (buffer[j] == '\n')
			j--;
		while (i < j) {
			ch = buffer[i];
			buffer[i] = buffer[j];
			buffer[j] = ch;
			i++;
			j--;
		}

		ret = sendto(fd, buffer, strlen(buffer) + 1, 0, (struct sockaddr *)&th_addr, sock_len);
		if (ret < 0) {
			perror("sendto");
			break;
		}
	}

out:
	if (fd >= 0) {
		close(fd);
	}
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

	if (argc != 2)
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
	io_args->port = atoi(argv[1]);;

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

