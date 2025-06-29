#include "contiki.h"
#include "net/routing/routing.h"
#include "random.h"
#include "net/netstack.h"
#include "net/ipv6/simple-udp.h"
#include "sys/log.h"
#include <stdint.h>
#include <inttypes.h>
#include <string.h>

#define LOG_MODULE "App"
#define LOG_LEVEL LOG_LEVEL_INFO

#define UDP_CLIENT_PORT 8765
#define UDP_SERVER_PORT 5678
#define SEND_INTERVAL (10 * CLOCK_SECOND)

static struct simple_udp_connection udp_conn;
static uint32_t rx_count = 0;
static bool initial_packet_sent = false;

/*---------------------------------------------------------------------------*/
PROCESS(udp_client_process, "UDP client (Blackhole Attacker)");
AUTOSTART_PROCESSES(&udp_client_process);
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
  // Log received packets but DO NOT forward them (Blackhole behavior)
  LOG_INFO("Received packet from ");
  LOG_INFO_6ADDR(sender_addr);
  LOG_INFO_(" (DROPPING, not forwarding)\n");
  rx_count++; // Optional: Track how many packets were dropped
}
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(udp_client_process, ev, data)
{
  static struct etimer periodic_timer;
  uip_ipaddr_t dest_ipaddr;

  PROCESS_BEGIN();

  simple_udp_register(&udp_conn, UDP_CLIENT_PORT, NULL,
                      UDP_SERVER_PORT, udp_rx_callback);

  etimer_set(&periodic_timer, SEND_INTERVAL);

  while(1) {
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&periodic_timer));

    if(NETSTACK_ROUTING.node_is_reachable() &&
       NETSTACK_ROUTING.get_root_ipaddr(&dest_ipaddr)) {

      if(!initial_packet_sent) {
        // Send one dummy packet to get registered in IDS
        char msg[] = "hello 0";
        simple_udp_sendto(&udp_conn, msg, strlen(msg), &dest_ipaddr);
        LOG_INFO("Blackhole: Sent initial dummy packet to server.\n");
        initial_packet_sent = true;
      } else {
        LOG_INFO("I am a Blackhole attacker (now silent).\n");
      }

    } else {
      LOG_INFO("Root not reachable\n");
    }

    etimer_set(&periodic_timer, SEND_INTERVAL);
  }

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
