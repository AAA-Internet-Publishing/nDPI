/*
 * ping_pong.c
 *
 * Copyright (C) 2020 - ntop.org
 *
 * nDPI is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * nDPI is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with nDPI.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include "ndpi_protocol_ids.h"

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_PING_PONG

#include "ndpi_api.h"

/*
Analysis for PingPong.
*/
static void ndpi_search_ping_pong(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {

    struct ndpi_packet_struct const *packet = &ndpi_struct->packet;

	puts("does it incrementally compiled");
	puts("does it incrementally compiled");
	
	
	/*	Inspect the client to server packet. If it contains the bytes "PONG", then 
	we conclude it's the PINGPONG protocol, otherwise stop searching. 
	*/
	if (ndpi_current_pkt_from_client_to_server(packet, flow)) {
		puts("client->server");
		if (packet->payload_packet_len > 3 
			&& packet->payload[0] == 0x70
			&& packet->payload[1] == 0x6f
			&& packet->payload[2] == 0x6e
			&& packet->payload[3] == 0x67) {
				ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_PING_PONG, NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
				return;
		} else {
			puts("client->server nomatch");
			NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
		}
	}

	/*	It's not "PONG", check for "PING". Inspect the client to server packet. If it contains the bytes "PING", then 
	we conclude it's the PINGPONG protocol, otherwise stop searching.
	*/
	if (ndpi_current_pkt_from_server_to_client(packet, flow)) {
		puts("server->client");
	  if (packet->payload_packet_len > 3 
			&& packet->payload[0] == 0x70
			&& packet->payload[1] == 0x69
			&& packet->payload[2] == 0x6e
			&& packet->payload[3] == 0x67) {
				ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_PING_PONG, NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
				return;
		} else {
			puts("server->client nomatch");
			NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
		}
	}

	return;
}

void init_ping_pong_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t * id) {
    ndpi_set_bitmask_protocol_detection("PingPong", ndpi_struct, *id,
                                        NDPI_PROTOCOL_PING_PONG,
                                        ndpi_search_ping_pong,
                                        NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD,
                                        SAVE_DETECTION_BITMASK_AS_UNKNOWN,
                                        ADD_TO_DETECTION_BITMASK);
    *id += 1;
}
