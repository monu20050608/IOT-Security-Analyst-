#include "contiki.h"
#include "net/routing/routing.h"
#include "net/netstack.h"
#include "net/ipv6/simple-udp.h"
#include "lib/memb.h"
#include "lib/list.h"
#include "sys/node-id.h"
#include "sys/log.h"
#include "string.h"
#include <stdlib.h>

#define LOG_MODULE "IDS_Server"
#define LOG_LEVEL LOG_LEVEL_INFO

#define UDP_CLIENT_PORT 8765
#define UDP_SERVER_PORT 5678
#define MAX_NODES 50
#define BLACKHOLE_TIMEOUT (30 * CLOCK_SECOND)
#define FLOOD_THRESHOLD 5
#define FLOOD_INTERVAL (10 * CLOCK_SECOND)

static struct simple_udp_connection udp_conn;

typedef struct {
  uip_ipaddr_t ip;
  uint32_t last_msg_id;
  clock_time_t last_seen;
  uint8_t recent_count;
  clock_time_t last_reset_time;
} node_info_t;

static node_info_t nodes[MAX_NODES];

PROCESS(udp_server_process, "UDP server with IDS");
AUTOSTART_PROCESSES(&udp_server_process);

/*---------------------------------------------------------------------------*/
static int find_or_add_node(const uip_ipaddr_t *addr) {
  for(int i = 0; i < MAX_NODES; i++) {
    if(uip_ipaddr_cmp(&nodes[i].ip, addr)) {
      return i;
    }
  }
  for(int i = 0; i < MAX_NODES; i++) {
    if(uip_is_addr_unspecified(&nodes[i].ip)) {
      uip_ipaddr_copy(&nodes[i].ip, addr);
      nodes[i].last_seen = clock_time();
      nodes[i].last_msg_id = 0;
      nodes[i].recent_count = 0;
      nodes[i].last_reset_time = clock_time();
      return i;
    }
  }
  return -1; // Table full
}
/*---------------------------------------------------------------------------*/
static void
udp_rx_callback(struct simple_udp_connection *c,
                const uip_ipaddr_t *sender_addr,
                uint16_t sender_port,
                const uip_ipaddr_t *receiver_addr,
                uint16_t receiver_port,
                const uint8_t *data,
                uint16_t datalen)
{
  LOG_INFO("Received '%.*s' from ", datalen, (char *)data);
  LOG_INFO_6ADDR(sender_addr);
  LOG_INFO_("\n");

  int id = find_or_add_node(sender_addr);
  if(id == -1) {
    LOG_WARN("Node table full, cannot track new node!\n");
    return;
  }

  // Extract message ID from "hello <msg_id>"
  char buffer[32];
  memcpy(buffer, data, datalen);
  buffer[datalen] = '\0';
  uint32_t msg_id = atoi(&buffer[6]); // Skipping "hello "

  // Replay detection
  if(msg_id == nodes[id].last_msg_id) {
    LOG_WARN("Replay attack detected from ");
    LOG_WARN_6ADDR(sender_addr);
    LOG_WARN_("\n");
  }
  nodes[id].last_msg_id = msg_id;

  // Flooding detection with interval reset
  clock_time_t now = clock_time();
  if(now - nodes[id].last_reset_time > FLOOD_INTERVAL) {
    nodes[id].recent_count = 1;
    nodes[id].last_reset_time = now;
  } else {
    nodes[id].recent_count++;
  }

  if(nodes[id].recent_count > FLOOD_THRESHOLD) {
    LOG_WARN("Flooding detected from ");
    LOG_WARN_6ADDR(sender_addr);
    LOG_WARN_("\n");
    nodes[id].recent_count = 0;
    nodes[id].last_reset_time = now;
  }

  nodes[id].last_seen = now;

#if WITH_SERVER_REPLY
  simple_udp_sendto(&udp_conn, data, datalen, sender_addr);
#endif
}
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(udp_server_process, ev, data)
{
  static struct etimer check_timer;
  PROCESS_BEGIN();

  NETSTACK_ROUTING.root_start();
  simple_udp_register(&udp_conn, UDP_SERVER_PORT, NULL,
                      UDP_CLIENT_PORT, udp_rx_callback);

  etimer_set(&check_timer, 30 * CLOCK_SECOND);

  while(1) {
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&check_timer));

    clock_time_t now = clock_time();

    for(int i = 0; i < MAX_NODES; i++) {
      if(!uip_is_addr_unspecified(&nodes[i].ip)) {
        if((now - nodes[i].last_seen) > BLACKHOLE_TIMEOUT) {
          LOG_WARN("Possible blackhole detected: ");
          LOG_WARN_6ADDR(&nodes[i].ip);
          LOG_WARN_("\n");
        }
      }
    }

    etimer_reset(&check_timer);
  }

  PROCESS_END();
}
