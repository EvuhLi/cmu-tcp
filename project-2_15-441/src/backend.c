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
 * This file implements the CMU-TCP backend. The backend runs in a different
 * thread and handles all the socket operations separately from the application.
 *
 * This is where most of your code should go. Feel free to modify any function
 * in this file.
 */

#include "backend.h"

#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>

#include "cmu_packet.h"
#include "cmu_tcp.h"

#define MIN(X, Y) (((X) < (Y)) ? (X) : (Y))

#define SMALL_POLL_MS 10

void handle_ack(cmu_socket_t *sock, uint32_t ack) {
  while (pthread_mutex_lock(&(sock->send_lock)) != 0) {
  }

  if (after(ack, sock->window.last_ack_received) &&
      !after(ack, sock->window.max_seq_sent)) {
    uint32_t acked = ack - sock->window.last_ack_received;
    uint32_t remaining = (uint32_t)sock->sending_len - acked;
    if (remaining > 0) {
      memmove(sock->sending_buf, sock->sending_buf + acked, remaining);
      sock->sending_buf = realloc(sock->sending_buf, remaining);
    } else {
      free(sock->sending_buf);
      sock->sending_buf = NULL;
    }
    sock->sending_len = remaining;
    sock->window.last_ack_received = ack;
    if (after(ack, sock->window.next_seq_to_send)) {
      sock->window.next_seq_to_send = ack;
    }

    if (sock->window.last_ack_received == sock->window.next_seq_to_send) {
      sock->timer_running = 0;
    } else {
      clock_gettime(CLOCK_MONOTONIC, &(sock->timer_start));
    }
  }

  pthread_mutex_unlock(&(sock->send_lock));
}

static void send_ctrl(cmu_socket_t *sock, uint32_t seq, uint32_t ack,
                      uint8_t flags) {
  socklen_t conn_len = sizeof(sock->conn);
  uint16_t src = sock->my_port;
  uint16_t dst = ntohs(sock->conn.sin_port);
  uint16_t hlen = sizeof(cmu_tcp_header_t);
  uint8_t *pkt = create_packet(src, dst, seq, ack, hlen, hlen, flags, 1, 0,
                               NULL, NULL, 0);
  sendto(sock->socket, pkt, hlen, 0, (struct sockaddr *)&(sock->conn),
         conn_len);
  free(pkt);
}

static void sync_send_window(cmu_socket_t *sock) {
  while (pthread_mutex_lock(&(sock->send_lock)) != 0) {
  }
  sock->window.last_ack_received = sock->isn + 1;
  sock->window.next_seq_to_send = sock->isn + 1;
  sock->window.max_seq_sent = sock->isn + 1;
  sock->timer_running = 0;
  pthread_mutex_unlock(&(sock->send_lock));
}

static void handle_syn(cmu_socket_t *sock, uint8_t flags, uint32_t seq,
                       uint32_t ack) {
  int has_ack = flags & ACK_FLAG_MASK;

  if (sock->conn_state == LISTEN && !has_ack) {
    sock->peer_isn = seq;
    sock->window.next_seq_expected = seq + 1;
    send_ctrl(sock, sock->isn, sock->peer_isn + 1,
              SYN_FLAG_MASK | ACK_FLAG_MASK);
    while (pthread_mutex_lock(&(sock->send_lock)) != 0) {
    }
    clock_gettime(CLOCK_MONOTONIC, &(sock->timer_start));
    sock->timer_running = 1;
    pthread_mutex_unlock(&(sock->send_lock));
    sock->conn_state = SYN_RCVD;
    return;
  }

  if (sock->conn_state == SYN_RCVD && !has_ack) {
    if (seq == sock->peer_isn) {
      send_ctrl(sock, sock->isn, sock->peer_isn + 1,
                SYN_FLAG_MASK | ACK_FLAG_MASK);
    }
    return;
  }

  if (sock->conn_state == SYN_SENT && has_ack) {
    if (ack != sock->isn + 1) return;
    sock->peer_isn = seq;
    sock->window.next_seq_expected = seq + 1;
    sync_send_window(sock);
    send_ctrl(sock, sock->isn + 1, sock->peer_isn + 1, ACK_FLAG_MASK);
    sock->conn_state = ESTABLISHED;
    pthread_cond_broadcast(&(sock->wait_cond));
    return;
  }

  if (sock->conn_state == ESTABLISHED && has_ack && seq == sock->peer_isn) {
    send_ctrl(sock, sock->window.next_seq_to_send,
              sock->window.next_seq_expected, ACK_FLAG_MASK);
    return;
  }

  if (sock->conn_state == ESTABLISHED && !has_ack && seq == sock->peer_isn) {
    send_ctrl(sock, sock->isn, sock->peer_isn + 1,
              SYN_FLAG_MASK | ACK_FLAG_MASK);
    return;
  }
}

/**
 * Updates the socket information to represent the newly received packet.
 *
 * @param sock The socket used for handling packets received.
 * @param pkt The packet data received by the socket.
 */
void handle_message(cmu_socket_t *sock, uint8_t *pkt) {
  cmu_tcp_header_t *hdr = (cmu_tcp_header_t *)pkt;
  if (ntohl(hdr->identifier) != IDENTIFIER) {
    return;
  }
  uint8_t flags = get_flags(hdr);
  uint32_t seq = get_seq(hdr);
  uint32_t ack = get_ack(hdr);

  if (flags & SYN_FLAG_MASK) {
    handle_syn(sock, flags, seq, ack);
    return;
  }

  if (sock->conn_state == SYN_RCVD && (flags & ACK_FLAG_MASK)) {
    if (ack != sock->isn + 1) return;
    sync_send_window(sock);
    sock->conn_state = ESTABLISHED;
    pthread_cond_broadcast(&(sock->wait_cond));
  }

  if (sock->conn_state != ESTABLISHED) {
    return;
  }

  if (flags & ACK_FLAG_MASK) {
    handle_ack(sock, ack);
  }

  uint16_t payload_len = get_payload_len(pkt);
  if (payload_len == 0) {
    return;
  }

  if (seq == sock->window.next_seq_expected) {
    uint8_t *payload = get_payload(pkt);
    sock->received_buf =
        realloc(sock->received_buf, sock->received_len + payload_len);
    memcpy(sock->received_buf + sock->received_len, payload, payload_len);
    sock->received_len += payload_len;
    sock->window.next_seq_expected += payload_len;
    pthread_cond_signal(&(sock->wait_cond));
  }

  send_ctrl(sock, sock->window.next_seq_to_send,
            sock->window.next_seq_expected, ACK_FLAG_MASK);
}

/**
 * Checks if the socket received any data.
 *
 * It first peeks at the header to figure out the length of the packet and then
 * reads the entire packet.
 *
 * @param sock The socket used for receiving data on the connection.
 * @param flags Flags that determine how the socket should wait for data. Check
 *             `cmu_read_mode_t` for more information.
 */
void check_for_data(cmu_socket_t *sock, cmu_read_mode_t flags) {
  cmu_tcp_header_t hdr;
  uint8_t *pkt;
  socklen_t conn_len = sizeof(sock->conn);
  ssize_t len = 0;
  uint32_t plen = 0, buf_size = 0, n = 0;

  while (pthread_mutex_lock(&(sock->recv_lock)) != 0) {
  }
  switch (flags) {
    case NO_FLAG:
      len = recvfrom(sock->socket, &hdr, sizeof(cmu_tcp_header_t), MSG_PEEK,
                     (struct sockaddr *)&(sock->conn), &conn_len);
      break;
    case TIMEOUT: {
      // Using `poll` here so that we can specify a timeout.
      struct pollfd ack_fd;
      ack_fd.fd = sock->socket;
      ack_fd.events = POLLIN;
      // Timeout after DEFAULT_TIMEOUT.
      if (poll(&ack_fd, 1, DEFAULT_TIMEOUT) <= 0) {
        break;
      }
    }
    // Fallthrough.
    case NO_WAIT:
      len = recvfrom(sock->socket, &hdr, sizeof(cmu_tcp_header_t),
                     MSG_DONTWAIT | MSG_PEEK, (struct sockaddr *)&(sock->conn),
                     &conn_len);
      break;
    default:
      perror("ERROR unknown flag");
  }
  if (len >= (ssize_t)sizeof(cmu_tcp_header_t)) {
    plen = get_plen(&hdr);
    pkt = malloc(plen);
    while (buf_size < plen) {
      n = recvfrom(sock->socket, pkt + buf_size, plen - buf_size, 0,
                   (struct sockaddr *)&(sock->conn), &conn_len);
      buf_size = buf_size + n;
    }
    handle_message(sock, pkt);
    free(pkt);
  }
  pthread_mutex_unlock(&(sock->recv_lock));
}

static conn_state_t get_conn_state(cmu_socket_t *sock) {
  while (pthread_mutex_lock(&(sock->recv_lock)) != 0) {
  }
  conn_state_t state = sock->conn_state;
  pthread_mutex_unlock(&(sock->recv_lock));
  return state;
}

void send_window(cmu_socket_t *sock) {
  size_t conn_len = sizeof(sock->conn);

  if (get_conn_state(sock) != ESTABLISHED) {
    return;
  }

  while (pthread_mutex_lock(&(sock->send_lock)) != 0) {
  }

  while (1) {
    uint32_t in_flight =
        sock->window.next_seq_to_send - sock->window.last_ack_received;
    uint32_t unsent = (uint32_t)sock->sending_len - in_flight;
    if (in_flight >= CP1_WINDOW_SIZE || unsent == 0) {
      break;
    }

    uint16_t payload_len =
        MIN(MIN((uint32_t)MSS, CP1_WINDOW_SIZE - in_flight), unsent);
    uint8_t *payload = sock->sending_buf + in_flight;

    uint16_t src = sock->my_port;
    uint16_t dst = ntohs(sock->conn.sin_port);
    uint32_t seq = sock->window.next_seq_to_send;
    uint32_t ack = sock->window.next_seq_expected;
    uint16_t hlen = sizeof(cmu_tcp_header_t);
    uint16_t plen = hlen + payload_len;
    uint8_t flags = ACK_FLAG_MASK;
    uint16_t adv_window = 1;
    uint16_t ext_len = 0;
    uint8_t *ext_data = NULL;

    uint8_t *msg = create_packet(src, dst, seq, ack, hlen, plen, flags,
                                 adv_window, ext_len, ext_data, payload,
                                 payload_len);
    sendto(sock->socket, msg, plen, 0, (struct sockaddr *)&(sock->conn),
           conn_len);
    free(msg);

    if (!sock->timer_running) {
      clock_gettime(CLOCK_MONOTONIC, &(sock->timer_start));
      sock->timer_running = 1;
    }
    sock->window.next_seq_to_send += payload_len;
    if (after(sock->window.next_seq_to_send, sock->window.max_seq_sent)) {
      sock->window.max_seq_sent = sock->window.next_seq_to_send;
    }
  }

  pthread_mutex_unlock(&(sock->send_lock));
}

static long ms_since(const struct timespec *start) {
  struct timespec now;
  clock_gettime(CLOCK_MONOTONIC, &now);
  return (now.tv_sec - start->tv_sec) * 1000 +
         (now.tv_nsec - start->tv_nsec) / 1000000;
}

static void check_timer(cmu_socket_t *sock) {
  while (pthread_mutex_lock(&(sock->send_lock)) != 0) {
  }
  int expired = sock->timer_running &&
                ms_since(&(sock->timer_start)) >= DEFAULT_TIMEOUT;
  pthread_mutex_unlock(&(sock->send_lock));
  if (!expired) return;

  conn_state_t state = get_conn_state(sock);

  if (state == SYN_SENT) {
    send_ctrl(sock, sock->isn, 0, SYN_FLAG_MASK);
  } else if (state == SYN_RCVD) {
    send_ctrl(sock, sock->isn, sock->peer_isn + 1,
              SYN_FLAG_MASK | ACK_FLAG_MASK);
  }

  while (pthread_mutex_lock(&(sock->send_lock)) != 0) {
  }
  if (state == SYN_SENT || state == SYN_RCVD) {
    clock_gettime(CLOCK_MONOTONIC, &(sock->timer_start));
  } else if (state == ESTABLISHED) {
    sock->window.next_seq_to_send = sock->window.last_ack_received;
    sock->timer_running = 0;
  }
  pthread_mutex_unlock(&(sock->send_lock));
}

void *begin_backend(void *in) {
  cmu_socket_t *sock = (cmu_socket_t *)in;
  int death, buf_len, send_signal;
  int wait_ms;

  while (1) {
    while (pthread_mutex_lock(&(sock->send_lock)) != 0) {
    }
    if (sock->timer_running) {
      wait_ms = DEFAULT_TIMEOUT - ms_since(&(sock->timer_start));
      if (wait_ms < 0) wait_ms = 0;
    } else {
      wait_ms = SMALL_POLL_MS;
    }
    pthread_mutex_unlock(&(sock->send_lock));

    struct pollfd fd;
    fd.fd = sock->socket;
    fd.events = POLLIN;
    if (poll(&fd, 1, wait_ms) > 0) {
      check_for_data(sock, NO_WAIT);
    }

    check_timer(sock);

    send_window(sock);

    while (pthread_mutex_lock(&(sock->recv_lock)) != 0) {
    }
    send_signal = sock->received_len > 0;
    pthread_mutex_unlock(&(sock->recv_lock));

    if (send_signal) {
      pthread_cond_signal(&(sock->wait_cond));
    }

    while (pthread_mutex_lock(&(sock->death_lock)) != 0) {
    }
    death = sock->dying;
    pthread_mutex_unlock(&(sock->death_lock));

    while (pthread_mutex_lock(&(sock->send_lock)) != 0) {
    }
    buf_len = sock->sending_len;
    pthread_mutex_unlock(&(sock->send_lock));

    if (death && get_conn_state(sock) == ESTABLISHED && buf_len == 0) {
      break;
    }
  }

  pthread_exit(NULL);
  return NULL;
}
