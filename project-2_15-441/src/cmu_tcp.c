/**
 * Copyright (C) 2022 Carnegie Mellon University
 *
 * This file is part of the TCP in the Wild course project developed for the
 * Computer Networks course (15-441/641) taught at Carnegie Mellon University.
 *
 * No part of the project may be copied and/or distributed without the express
 * permission of the 15-441/641 course staff.
 *
 *
 * This file implements the high-level API for CMU-TCP sockets.
 */

#include "cmu_tcp.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "backend.h"

static uint32_t random_isn(void) {
  uint32_t isn;
  FILE *f = fopen("/dev/urandom", "rb");
  if (f != NULL) {
    size_t n = fread(&isn, sizeof(isn), 1, f);
    fclose(f);
    if (n == 1) return isn;
  }
  static int seeded = 0;
  if (!seeded) {
    srand((unsigned)time(NULL) ^ (unsigned)getpid());
    seeded = 1;
  }
  return ((uint32_t)rand() << 16) ^ (uint32_t)rand();
}

int cmu_socket(cmu_socket_t *sock, const cmu_socket_type_t socket_type,
               const int port, const char *server_ip) {
  int sockfd, optval;
  socklen_t len;
  struct sockaddr_in conn, my_addr;
  len = sizeof(my_addr);

  sockfd = socket(AF_INET, SOCK_DGRAM, 0);
  if (sockfd < 0) {
    perror("ERROR opening socket");
    return EXIT_ERROR;
  }
  sock->socket = sockfd;
  sock->received_buf = NULL;
  sock->received_len = 0;
  pthread_mutex_init(&(sock->recv_lock), NULL);

  sock->sending_buf = NULL;
  sock->sending_len = 0;
  pthread_mutex_init(&(sock->send_lock), NULL);

  sock->type = socket_type;
  sock->dying = 0;
  pthread_mutex_init(&(sock->death_lock), NULL);

  sock->isn = random_isn();
  sock->window.last_ack_received = sock->isn;
  sock->window.next_seq_expected = 0;
  sock->window.next_seq_to_send = sock->isn;
  sock->window.max_seq_sent = sock->isn;
  sock->conn_state = CLOSED;
  sock->peer_isn = 0;
  sock->timer_running = 0;
  sock->window.right_edge = sock->isn;
  sock->ooo_head = NULL;
  sock->last_adv_window = MAX_NETWORK_BUFFER;
  sock->window_update_pending = 0;
  sock->cwnd = WINDOW_INITIAL_WINDOW_SIZE;
  sock->ssthresh = WINDOW_INITIAL_SSTHRESH;
  sock->cc_state = SLOW_START;
  sock->dup_acks = 0;
  sock->ca_acc = 0;
  sock->fast_retx_pending = 0;
  sock->cwnd_log = fopen(socket_type == TCP_INITIATOR ? "cwnd_initiator.csv"
                                                      : "cwnd_listener.csv",
                         "w");
  if (sock->cwnd_log != NULL) {
    fprintf(sock->cwnd_log, "ms,cwnd,ssthresh,state,event\n");
  }
  clock_gettime(CLOCK_MONOTONIC, &(sock->log_start));

  if (pthread_cond_init(&sock->wait_cond, NULL) != 0) {
    perror("ERROR condition variable not set\n");
    return EXIT_ERROR;
  }

  switch (socket_type) {
    case TCP_INITIATOR:
      if (server_ip == NULL) {
        perror("ERROR server_ip NULL");
        return EXIT_ERROR;
      }
      memset(&conn, 0, sizeof(conn));
      conn.sin_family = AF_INET;
      conn.sin_addr.s_addr = inet_addr(server_ip);
      conn.sin_port = htons(port);
      sock->conn = conn;

      my_addr.sin_family = AF_INET;
      my_addr.sin_addr.s_addr = htonl(INADDR_ANY);
      my_addr.sin_port = 0;
      if (bind(sockfd, (struct sockaddr *)&my_addr, sizeof(my_addr)) < 0) {
        perror("ERROR on binding");
        return EXIT_ERROR;
      }

      break;

    case TCP_LISTENER:
      memset(&conn, 0, sizeof(conn));
      conn.sin_family = AF_INET;
      conn.sin_addr.s_addr = htonl(INADDR_ANY);
      conn.sin_port = htons((uint16_t)port);

      optval = 1;
      setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (const void *)&optval,
                 sizeof(int));
      if (bind(sockfd, (struct sockaddr *)&conn, sizeof(conn)) < 0) {
        perror("ERROR on binding");
        return EXIT_ERROR;
      }
      sock->conn = conn;
      break;

    default:
      perror("Unknown Flag");
      return EXIT_ERROR;
  }
  getsockname(sockfd, (struct sockaddr *)&my_addr, &len);
  sock->my_port = ntohs(my_addr.sin_port);

  if (socket_type == TCP_LISTENER) {
    sock->conn_state = LISTEN;
  } else {
    uint16_t hlen = sizeof(cmu_tcp_header_t);
    uint8_t *syn = create_packet(sock->my_port, ntohs(sock->conn.sin_port),
                                 sock->isn, 0, hlen, hlen, SYN_FLAG_MASK,
                                 MAX_NETWORK_BUFFER, 0,
                                 NULL, NULL, 0);
    sendto(sockfd, syn, hlen, 0, (struct sockaddr *)&(sock->conn),
           sizeof(sock->conn));
    free(syn);
    sock->conn_state = SYN_SENT;
    clock_gettime(CLOCK_MONOTONIC, &(sock->timer_start));
    sock->timer_running = 1;
  }

  pthread_create(&(sock->thread_id), NULL, begin_backend, (void *)sock);

  while (pthread_mutex_lock(&(sock->recv_lock)) != 0) {
  }
  while (sock->conn_state != ESTABLISHED) {
    pthread_cond_wait(&(sock->wait_cond), &(sock->recv_lock));
  }
  pthread_mutex_unlock(&(sock->recv_lock));
  return EXIT_SUCCESS;
}

int cmu_close(cmu_socket_t *sock) {
  while (pthread_mutex_lock(&(sock->death_lock)) != 0) {
  }
  sock->dying = 1;
  pthread_mutex_unlock(&(sock->death_lock));

  pthread_join(sock->thread_id, NULL);

  if (sock != NULL) {
    if (sock->received_buf != NULL) {
      free(sock->received_buf);
    }
    if (sock->sending_buf != NULL) {
      free(sock->sending_buf);
    }
    if (sock->cwnd_log != NULL) {
      fclose(sock->cwnd_log);
      sock->cwnd_log = NULL;
    }
    while (sock->ooo_head != NULL) {
      ooo_seg_t *next = sock->ooo_head->next;
      free(sock->ooo_head->data);
      free(sock->ooo_head);
      sock->ooo_head = next;
    }
  } else {
    perror("ERROR null socket\n");
    return EXIT_ERROR;
  }
  return close(sock->socket);
}

int cmu_read(cmu_socket_t *sock, void *buf, int length, cmu_read_mode_t flags) {
  uint8_t *new_buf;
  int read_len = 0;

  if (length < 0) {
    perror("ERROR negative length");
    return EXIT_ERROR;
  }

  while (pthread_mutex_lock(&(sock->recv_lock)) != 0) {
  }

  switch (flags) {
    case NO_FLAG:
      while (sock->received_len == 0) {
        pthread_cond_wait(&(sock->wait_cond), &(sock->recv_lock));
      }
    // Fall through.
    case NO_WAIT:
      if (sock->received_len > 0) {
        if (sock->received_len > length)
          read_len = length;
        else
          read_len = sock->received_len;

        memcpy(buf, sock->received_buf, read_len);
        if (read_len < sock->received_len) {
          new_buf = malloc(sock->received_len - read_len);
          memcpy(new_buf, sock->received_buf + read_len,
                 sock->received_len - read_len);
          free(sock->received_buf);
          sock->received_len -= read_len;
          sock->received_buf = new_buf;
        } else {
          free(sock->received_buf);
          sock->received_buf = NULL;
          sock->received_len = 0;
        }
        // Window reopened after we advertised 0: ask backend to tell sender.
        if (sock->last_adv_window == 0 &&
            MAX_NETWORK_BUFFER - sock->received_len > 0) {
          sock->window_update_pending = 1;
        }
      }
      break;
    default:
      perror("ERROR Unknown flag.\n");
      read_len = EXIT_ERROR;
  }
  pthread_mutex_unlock(&(sock->recv_lock));
  return read_len;
}

int cmu_write(cmu_socket_t *sock, const void *buf, int length) {
  while (pthread_mutex_lock(&(sock->send_lock)) != 0) {
  }
  if (sock->sending_buf == NULL)
    sock->sending_buf = malloc(length);
  else
    sock->sending_buf = realloc(sock->sending_buf, length + sock->sending_len);
  memcpy(sock->sending_buf + sock->sending_len, buf, length);
  sock->sending_len += length;

  pthread_mutex_unlock(&(sock->send_lock));
  return EXIT_SUCCESS;
}
