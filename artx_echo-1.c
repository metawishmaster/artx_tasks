#include <ev.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>

#define BUF_SZ 1024

struct client {
	ev_io watcher;
	struct client *next;
	struct client *prev;
};

struct client *clients = NULL;

void free_clients()
{
	struct client *client = clients, *tmp;

	while (client) {
		printf("free %p\n", client);
		tmp = client;
		client = client->next;
		free(tmp);
	}
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

void read_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	char buffer[BUF_SZ];
	struct client *clnt;
	ssize_t read;

	if (EV_ERROR & revents) {
		perror("invalid event");
		return;
	}

	read = recv(watcher->fd, buffer, BUF_SZ, 0);

	if (read < 0) {
		perror("read error");
		return;
	}

	if (read == 0) {
		ev_io_stop(loop, watcher);
		clnt = (struct client*)watcher;
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

		printf("client %p closed\n", clnt);
		free(clnt);
		return;
	} else {
		buffer[read] = '\0';
		if (!strncmp(buffer, "quit", 4)) {
			ev_io_stop(loop, watcher);
			ev_loop_destroy(loop);
			free_clients();
			ev_break(loop, EVBREAK_ONE);
			return;
		}
		printf("message: %s\n", buffer);
	}

	send(watcher->fd, buffer, read, 0);
	bzero(buffer, read);
}

void accept_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	struct sockaddr_in client_addr;
	struct client *client;
	socklen_t client_len;
	int fd;

	client_len = sizeof(client_addr);
	client = (struct client*)malloc(sizeof(struct client));
	if (!client)
		return;

	client->prev = client->next = NULL;

	if (EV_ERROR & revents) {
		perror("invalid event");
		free(client);
		return;
	}

	fd = accept(watcher->fd, (struct sockaddr *)&client_addr, &client_len);

	if (fd < 0) {
		perror("accept");
		free(client);
		return;
	}

	ev_io_init(&(client->watcher), read_cb, fd, EV_READ);
	ev_io_start(loop, &(client->watcher));
	add_client(client);
}

int main(int argc, char **argv)
{
	struct ev_loop *loop;
	struct ev_io w_accept;
	struct sockaddr_in addr;
	struct client client;
	int addr_len = sizeof(addr);
	int sock;
	int opt = 1;

	if (argc != 2) {
		printf("usage: %s <port>\n", argv[0]);
		return -1;
	}

	loop = EV_DEFAULT;

	if ((sock = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
		perror("socket");
		return -1;
	}

	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) == -1) {
		perror("setsockopt");
	}

	bzero(&addr, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(atoi(argv[1]));
	addr.sin_addr.s_addr = INADDR_ANY;

	if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
		perror("bind");
	}

	if (listen(sock, 2) < 0) {
		perror("listen");
		return -1;
	}

	ev_io_init(&w_accept, accept_cb, sock, EV_READ);
	ev_io_start(loop, &w_accept);

	ev_loop(loop, 0);
out:
	printf("BYE\n");
	return 0;
}

