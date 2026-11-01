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

// Receiver window we can currently offer. Caller must hold recv_lock.
static uint16_t recv_window(cmu_socket_t *sock) {
  return (uint16_t)(MAX_NETWORK_BUFFER - sock->received_len);
}

#define MAX(X, Y) (((X) > (Y)) ? (X) : (Y))

static const char *cc_name(cc_state_t s) {
  switch (s) {
    case SLOW_START:
      return "SS";
    case CONG_AVOID:
      return "CA";
    case FAST_RECOVERY:
      return "FR";
  }
  return "?";
}

static long ms_since(const struct timespec *start);

// Appends ms,cwnd,ssthresh,state,event to the CSV. Caller holds send_lock.
static void log_cwnd(cmu_socket_t *sock, const char *event) {
  if (sock->cwnd_log == NULL) return;
  fprintf(sock->cwnd_log, "%ld,%u,%u,%s,%s\n", ms_since(&(sock->log_start)),
          sock->cwnd, sock->ssthresh, cc_name(sock->cc_state), event);
}

// Receiver-limited with nothing real in flight (only a probe, if anything).
// Relies on the invariant next_seq_to_send <= right_edge (apart from the
// 1-byte probe), which handle_ack restores when it accepts a shrink.
// Caller holds send_lock.
static int rwnd_closed(cmu_socket_t *sock) {
  return sock->window.right_edge == sock->window.last_ack_received;
}

// ssthresh = MAX(cwnd / 2, 2 * MSS). Caller holds send_lock.
static void halve(cmu_socket_t *sock) {
  sock->ssthresh = MAX(sock->cwnd / 2, 2 * (uint32_t)MSS);
}

void handle_ack(cmu_socket_t *sock, uint32_t seq, uint32_t ack, uint16_t adv,
                uint16_t payload_len) {
  while (pthread_mutex_lock(&(sock->send_lock)) != 0) {
  }

  // Ignore stale (ack < last_ack) or bogus (ack > last_sent) ACKs.
  if (before(ack, sock->window.last_ack_received) ||
      after(ack, sock->window.max_seq_sent)) {
    pthread_mutex_unlock(&(sock->send_lock));
    return;
  }

  if (after(ack, sock->window.last_ack_received)) {
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

    // Congestion control: new ACK.
    sock->dup_acks = 0;
    if (sock->cc_state == SLOW_START) {
      sock->cwnd += (uint32_t)MSS;
      if (sock->cwnd >= sock->ssthresh) {
        sock->cc_state = CONG_AVOID;
        sock->ca_acc = 0;
        log_cwnd(sock, "ss_to_ca");
      } else {
        log_cwnd(sock, "new_ack");
      }
    } else if (sock->cc_state == CONG_AVOID) {
      sock->ca_acc += (uint32_t)MSS;
      if (sock->ca_acc >= sock->cwnd) {
        sock->ca_acc -= sock->cwnd;
        sock->cwnd += (uint32_t)MSS;
      }
      log_cwnd(sock, "new_ack");
    } else {  // FAST_RECOVERY: deflate and go to CA.
      sock->cwnd = sock->ssthresh;
      sock->cc_state = CONG_AVOID;
      sock->ca_acc = 0;
      log_cwnd(sock, "exit_fr");
    }
  } else {
    // ack == last_ack: duplicate only if it carries no data, data is
    // outstanding, adv != 0 (not a probe reply), the window was open before
    // this ACK (not a window update), and the receiver's window covers
    // everything sent (receiver didn't drop data past its edge).
    // Checked before right_edge moves.
    int is_dup = payload_len == 0 &&
                 sock->window.last_ack_received != sock->window.max_seq_sent &&
                 adv != 0 && !rwnd_closed(sock) &&
                 !before(ack + adv, sock->window.max_seq_sent);
    if (is_dup) {
      if (sock->cc_state == FAST_RECOVERY) {
        sock->cwnd += (uint32_t)MSS;
        log_cwnd(sock, "dup_inflate");
      } else {
        sock->dup_acks++;
        if (sock->dup_acks == 3) {
          halve(sock);
          sock->cwnd = sock->ssthresh + 3 * (uint32_t)MSS;
          sock->cc_state = FAST_RECOVERY;
          sock->fast_retx_pending = 1;
          log_cwnd(sock, "3dup");
        } else {
          log_cwnd(sock, "dup");
        }
      }
    }
  }

  // WL1/WL2 rule: the most recently arrived ACK that isn't older wins.
  // The edge may shrink.
  if (after(seq, sock->window.wl1) ||
      (seq == sock->window.wl1 && !before(ack, sock->window.wl2))) {
    sock->window.right_edge = ack + adv;
    sock->window.wl1 = seq;
    sock->window.wl2 = ack;
    // Shrunk below what we sent: treat bytes past the edge as unsent.
    // max_seq_sent is left alone (the bogus-ACK check needs it).
    if (after(sock->window.next_seq_to_send, sock->window.right_edge)) {
      sock->window.next_seq_to_send = sock->window.right_edge;
      if (sock->window.next_seq_to_send == sock->window.last_ack_received) {
        sock->timer_running = 0;
      }
    }
  }

  pthread_mutex_unlock(&(sock->send_lock));
}

static void send_ctrl(cmu_socket_t *sock, uint32_t seq, uint32_t ack,
                      uint8_t flags, uint16_t adv) {
  socklen_t conn_len = sizeof(sock->conn);
  uint16_t src = sock->my_port;
  uint16_t dst = ntohs(sock->conn.sin_port);
  uint16_t hlen = sizeof(cmu_tcp_header_t);
  uint8_t *pkt = create_packet(src, dst, seq, ack, hlen, hlen, flags, adv, 0,
                               NULL, NULL, 0);
  sendto(sock->socket, pkt, hlen, 0, (struct sockaddr *)&(sock->conn),
         conn_len);
  free(pkt);
}

static void sync_send_window(cmu_socket_t *sock, uint16_t adv, uint32_t seq,
                             uint32_t ack) {
  while (pthread_mutex_lock(&(sock->send_lock)) != 0) {
  }
  sock->window.last_ack_received = sock->isn + 1;
  sock->window.next_seq_to_send = sock->isn + 1;
  sock->window.max_seq_sent = sock->isn + 1;
  sock->window.right_edge = sock->isn + 1 + adv;
  sock->window.wl1 = seq;
  sock->window.wl2 = ack;
  sock->timer_running = 0;
  sock->cwnd = WINDOW_INITIAL_WINDOW_SIZE;
  sock->ssthresh = WINDOW_INITIAL_SSTHRESH;
  sock->cc_state = SLOW_START;
  sock->dup_acks = 0;
  sock->ca_acc = 0;
  sock->fast_retx_pending = 0;
  log_cwnd(sock, "init");
  pthread_mutex_unlock(&(sock->send_lock));
}

static void handle_syn(cmu_socket_t *sock, uint8_t flags, uint32_t seq,
                       uint32_t ack, uint16_t adv) {
  int has_ack = flags & ACK_FLAG_MASK;

  if (sock->conn_state == LISTEN && !has_ack) {
    sock->peer_isn = seq;
    sock->window.next_seq_expected = seq + 1;
    send_ctrl(sock, sock->isn, sock->peer_isn + 1,
              SYN_FLAG_MASK | ACK_FLAG_MASK, MAX_NETWORK_BUFFER);
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
                SYN_FLAG_MASK | ACK_FLAG_MASK, MAX_NETWORK_BUFFER);
    }
    return;
  }

  if (sock->conn_state == SYN_SENT && has_ack) {
    if (ack != sock->isn + 1) return;
    sock->peer_isn = seq;
    sock->window.next_seq_expected = seq + 1;
    sync_send_window(sock, adv, seq, ack);
    send_ctrl(sock, sock->isn + 1, sock->peer_isn + 1, ACK_FLAG_MASK,
              recv_window(sock));
    sock->conn_state = ESTABLISHED;
    pthread_cond_broadcast(&(sock->wait_cond));
    return;
  }

  if (sock->conn_state == ESTABLISHED && has_ack && seq == sock->peer_isn) {
    send_ctrl(sock, sock->window.next_seq_to_send,
              sock->window.next_seq_expected, ACK_FLAG_MASK, recv_window(sock));
    return;
  }

  if (sock->conn_state == ESTABLISHED && !has_ack && seq == sock->peer_isn) {
    send_ctrl(sock, sock->isn, sock->peer_isn + 1,
              SYN_FLAG_MASK | ACK_FLAG_MASK, MAX_NETWORK_BUFFER);
    return;
  }
}

// Appends in-order bytes to received_buf. Caller holds recv_lock.
static void append_in_order(cmu_socket_t *sock, const uint8_t *data,
                            uint32_t len) {
  sock->received_buf = realloc(sock->received_buf, sock->received_len + len);
  memcpy(sock->received_buf + sock->received_len, data, len);
  sock->received_len += len;
  sock->window.next_seq_expected += len;
}

static ooo_seg_t *new_seg(uint32_t seq, uint32_t len, const uint8_t *data) {
  ooo_seg_t *seg = malloc(sizeof(ooo_seg_t));
  seg->seq = seq;
  seg->len = len;
  seg->data = malloc(len);
  memcpy(seg->data, data, len);
  seg->next = NULL;
  return seg;
}

// Inserts [start, end) into the sorted out-of-order list, keeping only the
// pieces that don't overlap segments already stored. Caller holds recv_lock.
static void insert_ooo(cmu_socket_t *sock, uint32_t start, uint32_t end,
                       const uint8_t *data) {
  ooo_seg_t **link = &(sock->ooo_head);
  uint32_t cur = start;

  while (*link != NULL && before(cur, end)) {
    ooo_seg_t *n = *link;
    uint32_t n_end = n->seq + n->len;
    if (!after(n_end, cur)) {  // Node entirely before cur.
      link = &(n->next);
      continue;
    }
    if (after(n->seq, cur)) {  // Gap before node: fill [cur, min(end, n->seq)).
      uint32_t piece_end = before(end, n->seq) ? end : n->seq;
      ooo_seg_t *seg = new_seg(cur, piece_end - cur, data + (cur - start));
      seg->next = n;
      *link = seg;
      link = &(seg->next);
    }
    if (after(n_end, cur)) cur = n_end;  // Skip bytes the node already has.
    link = &(n->next);
  }

  if (before(cur, end)) {  // Remainder goes at the tail.
    ooo_seg_t *seg = new_seg(cur, end - cur, data + (cur - start));
    seg->next = *link;
    *link = seg;
  }
}

// Moves now-contiguous out-of-order segments into received_buf.
// Caller holds recv_lock.
static void drain_ooo(cmu_socket_t *sock) {
  while (sock->ooo_head != NULL &&
         !after(sock->ooo_head->seq, sock->window.next_seq_expected)) {
    ooo_seg_t *seg = sock->ooo_head;
    uint32_t seg_end = seg->seq + seg->len;
    uint32_t next = sock->window.next_seq_expected;
    if (after(seg_end, next)) {
      append_in_order(sock, seg->data + (next - seg->seq), seg_end - next);
    }
    sock->ooo_head = seg->next;
    free(seg->data);
    free(seg);
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
  uint16_t adv = get_advertised_window(hdr);

  if (flags & SYN_FLAG_MASK) {
    handle_syn(sock, flags, seq, ack, adv);
    return;
  }

  if (sock->conn_state == SYN_RCVD && (flags & ACK_FLAG_MASK)) {
    if (ack != sock->isn + 1) return;
    sync_send_window(sock, adv, seq, ack);
    sock->conn_state = ESTABLISHED;
    pthread_cond_broadcast(&(sock->wait_cond));
  }

  if (sock->conn_state != ESTABLISHED) {
    return;
  }

  uint16_t payload_len = get_payload_len(pkt);
  if (flags & ACK_FLAG_MASK) {
    handle_ack(sock, seq, ack, adv, payload_len);
  }

  if (payload_len == 0) {
    return;
  }

  uint32_t next = sock->window.next_seq_expected;
  uint32_t right = next + (MAX_NETWORK_BUFFER - sock->received_len);
  uint8_t *payload = get_payload(pkt);

  // Trim the segment to [next_expected, right).
  uint32_t start = after(next, seq) ? next : seq;
  uint32_t end = seq + payload_len;
  if (after(end, right)) end = right;

  if (before(start, end)) {
    if (start == next) {
      append_in_order(sock, payload + (start - seq), end - start);
      drain_ooo(sock);
    } else {
      insert_ooo(sock, start, end, payload + (start - seq));
    }
    pthread_cond_signal(&(sock->wait_cond));
  }

  uint16_t win = recv_window(sock);
  send_ctrl(sock, sock->window.next_seq_to_send,
            sock->window.next_seq_expected, ACK_FLAG_MASK, win);
  sock->last_adv_window = win;
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

  // Snapshot receive-side values first (lock order: recv_lock -> send_lock).
  while (pthread_mutex_lock(&(sock->recv_lock)) != 0) {
  }
  uint32_t ack = sock->window.next_seq_expected;
  uint16_t adv_window = recv_window(sock);
  pthread_mutex_unlock(&(sock->recv_lock));

  while (pthread_mutex_lock(&(sock->send_lock)) != 0) {
  }

  // Fast retransmit: resend one segment at last_ack, regardless of usable.
  if (sock->fast_retx_pending) {
    sock->fast_retx_pending = 0;
    uint16_t len = MIN((uint32_t)MSS, (uint32_t)sock->sending_len);
    if (len > 0) {
      uint16_t hlen = sizeof(cmu_tcp_header_t);
      uint8_t *msg = create_packet(
          sock->my_port, ntohs(sock->conn.sin_port),
          sock->window.last_ack_received, ack, hlen, hlen + len, ACK_FLAG_MASK,
          adv_window, 0, NULL, sock->sending_buf, len);
      sendto(sock->socket, msg, hlen + len, 0,
             (struct sockaddr *)&(sock->conn), conn_len);
      free(msg);
      clock_gettime(CLOCK_MONOTONIC, &(sock->timer_start));
      sock->timer_running = 1;
    }
  }

  while (1) {
    uint32_t in_flight =
        sock->window.next_seq_to_send - sock->window.last_ack_received;
    uint32_t unsent = (uint32_t)sock->sending_len - in_flight;
    // Effective window = min(cwnd, rwnd), measured from last_ack.
    uint32_t rwnd = sock->window.right_edge - sock->window.last_ack_received;
    uint32_t win = MIN(sock->cwnd, rwnd);
    uint32_t limit = sock->window.last_ack_received + win;
    int32_t usable = (int32_t)(limit - sock->window.next_seq_to_send);

    uint16_t payload_len;
    if (usable > 0 && unsent > 0) {
      payload_len = MIN(MIN((uint32_t)MSS, (uint32_t)usable), unsent);
    } else if (rwnd_closed(sock) && in_flight == 0 && unsent > 0) {
      payload_len = 1;  // Zero-window probe.
    } else {
      break;
    }
    uint8_t *payload = sock->sending_buf + in_flight;

    uint16_t src = sock->my_port;
    uint16_t dst = ntohs(sock->conn.sin_port);
    uint32_t seq = sock->window.next_seq_to_send;
    uint16_t hlen = sizeof(cmu_tcp_header_t);
    uint16_t plen = hlen + payload_len;
    uint8_t flags = ACK_FLAG_MASK;
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
    send_ctrl(sock, sock->isn, 0, SYN_FLAG_MASK, MAX_NETWORK_BUFFER);
  } else if (state == SYN_RCVD) {
    send_ctrl(sock, sock->isn, sock->peer_isn + 1,
              SYN_FLAG_MASK | ACK_FLAG_MASK, MAX_NETWORK_BUFFER);
  }

  while (pthread_mutex_lock(&(sock->send_lock)) != 0) {
  }
  if (state == SYN_SENT || state == SYN_RCVD) {
    clock_gettime(CLOCK_MONOTONIC, &(sock->timer_start));
  } else if (state == ESTABLISHED) {
    // A probe timeout (receiver closed, only the probe outstanding) is not a
    // congestion signal: resend the probe, skip all CC changes.
    int probing = rwnd_closed(sock);
    sock->window.next_seq_to_send = sock->window.last_ack_received;
    sock->timer_running = 0;
    if (!probing) {
      halve(sock);
      sock->cwnd = WINDOW_INITIAL_WINDOW_SIZE;
      sock->cc_state = SLOW_START;
      sock->dup_acks = 0;
      sock->fast_retx_pending = 0;
      log_cwnd(sock, "timeout");
    }
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

    // Window-update ACK requested by cmu_read after a zero window reopened.
    while (pthread_mutex_lock(&(sock->recv_lock)) != 0) {
    }
    if (sock->window_update_pending) {
      uint16_t win = recv_window(sock);
      send_ctrl(sock, sock->window.next_seq_to_send,
                sock->window.next_seq_expected, ACK_FLAG_MASK, win);
      sock->last_adv_window = win;
      sock->window_update_pending = 0;
    }
    pthread_mutex_unlock(&(sock->recv_lock));

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
