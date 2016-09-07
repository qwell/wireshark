/* packet-enet.c
 *
 * Dissector for the UDP peer-to-peer protocol "enet".
 * Copyright 2016, Alexander Heinsius
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2015 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <epan/conversation.h>
#include <epan/packet.h>
#include <epan/reassemble.h>

/* These constants are copied from ENet's protocol.h
 * That source file is the best source for understanding the ENet protocol.
 */
#define ENET_PROTOCOL_MAXIMUM_PEER_ID 0xFFF

#define ENET_PROTOCOL_HEADER_SESSION_MASK 3 << 12
#define ENET_PROTOCOL_HEADER_SESSION_SHIFT 12
#define ENET_PROTOCOL_HEADER_FLAG_COMPRESSED 1 << 14
#define ENET_PROTOCOL_HEADER_FLAG_SENT_TIME  1 << 15

#define ENET_PROTOCOL_COMMAND_MASK 0x0F
#define ENET_PROTOCOL_COMMAND_FLAG_ACKNOWLEDGE 1 << 7
#define ENET_PROTOCOL_COMMAND_FLAG_UNSEQUENCED 1 << 6

static const value_string enet_commands[] = {
	{ 0, "None" },
	{ 1, "Acknowledge" },
	{ 2, "Connect" },
	{ 3, "Verify Connect" },
	{ 4, "Disconnect" },
	{ 5, "Ping" },
	{ 6, "Send Reliable" },
	{ 7, "Send Unreliable" },
	{ 8, "Send Fragment" },
	{ 9, "Send Unsequenced" },
	{ 10, "Bandwidth Limit" },
	{ 11, "Throttle Configure" },
	{ 12, "Send Unreliable Fragment" },
	{ 13, "Count" },
	{ 14, NULL }
};

static guint32 offset = 0;
static proto_tree *enet_tree = NULL;

static dissector_handle_t handle_data;
static heur_dissector_list_t heur_subdissector_list;

static reassembly_table msg_fragment_table;
GHashTable *table_reassembled_sequenceIDs = NULL;

static int proto_enet = -1;
static gint ett_enet_subtree = -1;
static gint ett_msg_fragment_subtree = -1;
static gint ett_msg_fragments_subtree = -1;

/* Protocol Header */
static int hf_peer_id = -1;
static int hf_flag_sent_time = -1;
static int hf_flag_compressed = -1;
static int hf_sent_time = -1;

/* Command Header */
static int hf_command = -1;
static int hf_command_acknowledge = -1;
static int hf_command_unsequenced = -1;
static int hf_channel = -1;
static int hf_sequence_number = -1;

/* Connection parameters */
static int hf_con_outgoing_peer_id = -1;
static int hf_con_mtu = -1;
static int hf_con_window_size = -1;
static int hf_con_channel_count = -1;
static int hf_con_incoming_session_id = -1;
static int hf_con_outgoing_session_id = -1;
static int hf_con_id = -1;
static int hf_con_data = -1;

/* Bandwidth */
static int hf_bandwidth_incoming = -1;
static int hf_bandwidth_outgoing = -1;

/* Throttle */
static int hf_throttle_interval = -1;
static int hf_throttle_accel = -1;
static int hf_throttle_decel = -1;

/* Acknowledge */
static int hf_ack_receive_time = -1;
static int hf_ack_received_sequence_number = -1;

/* Disconnect data */
static int hf_disconnect_data = -1;

/* Payload */
static int hf_payload = -1;
static int hf_payload_length = -1;

/* Unreliable */
static int hf_unreliable_sequence_number = -1;

/* Unsequenced */
static int hf_unsequenced_group = -1;

/* Fragment */
static int hf_fragment_start_sequence_number = -1;
static int hf_fragment_count = -1;
static int hf_fragment_number = -1;
static int hf_fragment_total = -1;
static int hf_fragment_offset = -1;

/* Reassembled Data */
static int hf_msg_fragments = -1;
static int hf_msg_fragment = -1;
static int hf_msg_fragment_overlap = -1;
static int hf_msg_fragment_overlap_conflicts = -1;
static int hf_msg_fragment_multiple_tails = -1;
static int hf_msg_fragment_too_long_fragment = -1;
static int hf_msg_fragment_error = -1;
static int hf_msg_fragment_count = -1;
static int hf_msg_reassembled_in = -1;
static int hf_msg_reassembled_length = -1;
static int hf_msg_reassembled_data = -1;

/* See https://www.wireshark.org/docs/wsar_html/epan/struct__header__field__info.html */
static hf_register_info hf_enet[] = {
	{ &hf_flag_sent_time,
		{ "Sent-Time Flag", "enet.flags.sent_time",
		FT_BOOLEAN, 16,
		NULL, ENET_PROTOCOL_HEADER_FLAG_SENT_TIME,
		"Whether or not the packet contains the time sent.", HFILL }
	},
	{ &hf_flag_compressed,
		{ "Compressed Flag", "enet.flags.compressed",
		FT_BOOLEAN, 16,
		NULL, ENET_PROTOCOL_HEADER_FLAG_COMPRESSED,
		"Whether or not the packet is compressed.", HFILL }
	},
	{ &hf_peer_id,
		{ "Peer ID", "enet.peer_id",
		FT_UINT16, BASE_DEC,
		NULL, ENET_PROTOCOL_MAXIMUM_PEER_ID,
		"A sequential number starting with 0 for the first client.", HFILL }
	},
	{ &hf_sent_time,
		{ "Sent Time", "enet.sent_time",
		FT_UINT16, BASE_DEC,
		NULL, 0x0,
		"Time when the packet was sent", HFILL } /* TODO: milliseconds after program start or what?*/
	},
	{ &hf_command_acknowledge,
		{ "Acknowledge Flag", "enet.flags.acknowledge",
		FT_BOOLEAN, 8,
		NULL, ENET_PROTOCOL_COMMAND_FLAG_ACKNOWLEDGE,
		NULL, HFILL }
	},
	{ &hf_command_unsequenced,
		{ "Unsequenced Flag", "enet.flags.unsequenced",
		FT_BOOLEAN, 8,
		NULL, ENET_PROTOCOL_COMMAND_FLAG_UNSEQUENCED,
		"Whether or not the command is unsequenced.", HFILL }
	},
	{ &hf_command,
		{ "Command", "enet.command",
		FT_UINT8, BASE_DEC,
		VALS(enet_commands), ENET_PROTOCOL_COMMAND_MASK,
		"Command of that packet.", HFILL }
	},
	{ &hf_channel,
		{ "Channel", "enet.channel",
		FT_UINT8, BASE_DEC,
		NULL, 0x0,
		"Channel on which the packet was sent.", HFILL }
	},
	{ &hf_sequence_number,
		{ "Sequence Number", "enet.sequence_number",
		FT_UINT16, BASE_DEC,
		NULL, 0x0,
		"Reliable sequence number of that packet.", HFILL }
	},
	{ &hf_con_outgoing_peer_id,
		{ "Outgoing Peer ID", "enet.connection.outgoing_peer_id",
		FT_UINT16, BASE_DEC,
		NULL, 0x0,
		"ID of the peer to which the connection is being established.", HFILL }
	},
	{ &hf_con_incoming_session_id,
		{ "Incoming Session ID", "enet.connection.incoming_session_id",
		FT_UINT8, BASE_DEC,
		NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_con_outgoing_session_id,
		{ "Outgoing Session ID", "enet.connection.outgoing_session_id",
		FT_UINT8, BASE_DEC,
		NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_con_mtu,
		{ "Maximum Transmission Unit", "enet.connection.mtu",
		FT_UINT32, BASE_DEC,
		NULL, 0x0,
		"Maximum Transmission Unit for enet packets", HFILL }
	},
	{ &hf_con_window_size,
		{ "Window Size", "enet.connection_window_size",
		FT_UINT32, BASE_DEC,
		NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_con_channel_count,
		{ "Channel Count", "enet.connection.channel_count",
		FT_UINT32, BASE_DEC,
		NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_con_id,
		{ "Connection ID", "enet.connection.id",
		FT_UINT32, BASE_DEC,
		NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_con_data,
		{ "Connect Data", "enet.connection.data",
		FT_UINT32, BASE_DEC,
		NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_bandwidth_incoming,
		{ "Incoming Bandwidth", "enet.bandwidth.incoming",
		FT_UINT32, BASE_DEC,
		NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_bandwidth_outgoing,
		{ "Outgoing Bandwidth", "enet.bandwidth.outgoing",
		FT_UINT32, BASE_DEC,
		NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_throttle_interval,
		{ "Throttle Interval", "enet.throttle.interval",
		FT_UINT32, BASE_DEC,
		NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_throttle_accel,
		{ "Throttle Acceleration", "enet.throttle.acceleration",
		FT_UINT32, BASE_DEC,
		NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_throttle_decel,
		{ "Throttle Deceleration", "enet.throttle.deceleration",
		FT_UINT32, BASE_DEC,
		NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_ack_received_sequence_number,
		{ "Received Sequence Number", "enet.acknowledge.received_sequence_number",
		FT_UINT16, BASE_DEC,
		NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_ack_receive_time,
		{ "Received Time", "enet.acknowledge.received_time",
		FT_UINT16, BASE_DEC,
		NULL, 0x0,
		"Time when the packet was received.", HFILL }
	},
	{ &hf_disconnect_data,
		{ "Disconnect Data", "enet.disconnect.data",
		FT_UINT32, BASE_DEC,
		NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_payload,
		{ "Payload", "enet.payload",
		FT_NONE, BASE_NONE,
		NULL, 0x0,
		"The application data that was transported with this package.", HFILL }
	},
	{ &hf_payload_length,
		{ "Payload Length", "enet.payload_length",
		FT_UINT16, BASE_DEC,
		NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_unreliable_sequence_number,
		{ "Unreliable Sequence Number", "enet.unreliable_sequence_number",
		FT_UINT16, BASE_DEC,
		NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_unsequenced_group,
		{ "Sequence Number", "enet.sequence_number",
		FT_UINT16, BASE_DEC,
		NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_fragment_start_sequence_number,
		{ "Fragment Start Sequence Number", "enet.fragment.start_sequence_number",
		FT_UINT16, BASE_DEC,
		NULL, 0x0,
		"Sequence number of the first fragment.", HFILL }
	},
	{ &hf_fragment_count,
		{ "Fragment Count", "enet.fragment.count", /* TODO: dont use enet.fragment.count twice*/
		FT_UINT32, BASE_DEC,
		NULL, 0x0,
		"Number of fragments that carry the payload.", HFILL }
	},
	{ &hf_fragment_number,
		{ "Fragment Number", "enet.fragment.number",
		FT_UINT32, BASE_DEC,
		NULL, 0x0,
		"Index of the current segment", HFILL } /* TODO: channels are used for multiple fragmented transfers*/
	},
	/* TODO: some things unused */
	{ &hf_fragment_total,
		{ "Fragment Total", "enet.fragment.total",
		FT_UINT32, BASE_DEC,
		NULL, 0x0,
		"Payload size in bytes", HFILL }
	},
	{ &hf_fragment_offset,
		{ "Fragment Offset", "enet.fragment.offset",
		FT_UINT32, BASE_DEC,
		NULL, 0x0,
		"Byte offset of the current fragment of the payload", HFILL }
	},
	{ &hf_msg_fragments,
		{ "Message fragments", "enet.fragments",
		FT_BYTES, BASE_NONE,
		NULL, 0x00,
		NULL, HFILL }
	},
	{ &hf_msg_fragment,
		{ "Message fragment", "enet.fragment",
		FT_FRAMENUM, BASE_NONE,
		NULL, 0x00,
		NULL, HFILL }
	},
	{ &hf_msg_fragment_overlap,
		{ "Message fragment overlap", "enet.fragment.overlap",
		FT_BOOLEAN, 0,
		NULL, 0x00,
		NULL, HFILL }
	},
	{ &hf_msg_fragment_overlap_conflicts,
		{ "Message fragment overlapping with conflicting data", "enet.fragment.overlap.conflicts",
		FT_BOOLEAN, 0,
		NULL, 0x00,
		NULL, HFILL }
	},
	{ &hf_msg_fragment_multiple_tails,
		{ "Message has multiple tail fragments", "enet.fragment.multiple_tails",
		FT_BOOLEAN, 0,
		NULL, 0x00,
		NULL, HFILL }
	},
	{ &hf_msg_fragment_too_long_fragment,
		{ "Message fragment too long", "enet.fragment.too_long_fragment",
		FT_BOOLEAN, 0,
		NULL, 0x00,
		NULL, HFILL }
	},
	{ &hf_msg_fragment_error,
		{ "Message defragmentation error", "enet.fragment.error",
		FT_FRAMENUM, BASE_NONE,
		NULL, 0x00,
		NULL, HFILL }
	},
	{ &hf_msg_fragment_count,
		{ "Message fragment count", "enet.fragment.count",
		FT_UINT32, BASE_DEC,
		NULL, 0x00,
		NULL, HFILL }
	},
	{ &hf_msg_reassembled_in,
		{ "Reassembled in", "enet.reassembled.in",
		FT_FRAMENUM, BASE_NONE,
		NULL, 0x00,
		NULL, HFILL }
	},
	{ &hf_msg_reassembled_length,
		{ "Reassembled length", "enet.reassembled.length",
		FT_UINT32, BASE_DEC,
		NULL, 0x00,
		NULL, HFILL }
	},
	{ &hf_msg_reassembled_data,
		{ "Reassembled data", "enet.reassembled.data",
		FT_BYTES, BASE_NONE,
		NULL, 0x00,
		NULL, HFILL }
	}
};

static const fragment_items msg_frag_items = {
	/* Fragment subtrees */
	&ett_msg_fragment_subtree,
	&ett_msg_fragments_subtree,
	/* Fragment fields */
	&hf_msg_fragments,
	&hf_msg_fragment,
	&hf_msg_fragment_overlap,
	&hf_msg_fragment_overlap_conflicts,
	&hf_msg_fragment_multiple_tails,
	&hf_msg_fragment_too_long_fragment,
	&hf_msg_fragment_error,
	&hf_msg_fragment_count,
	&hf_msg_reassembled_in,
	&hf_msg_reassembled_length,
	&hf_msg_reassembled_data,
	/* Tag */
	"Message fragments"
};

static void enet_dissect_payload(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	heur_dtbl_entry_t *hdtbl_entry;

	if (!dissector_try_heuristic(heur_subdissector_list, tvb, pinfo, tree, &hdtbl_entry, NULL))
		call_dissector(handle_data, tvb, pinfo, tree);
}

static void
dissect_enet_acknowledge(tvbuff_t *tvb, proto_tree *command_tree)
{
	proto_tree_add_item(command_tree, hf_ack_received_sequence_number, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	proto_tree_add_item(command_tree, hf_ack_receive_time, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
}

static void
dissect_enet_bandwidth_limit(tvbuff_t *tvb, proto_tree *command_tree)
{
	proto_tree_add_item(command_tree, hf_bandwidth_incoming, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	proto_tree_add_item(command_tree, hf_bandwidth_outgoing, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
}

static void
dissect_enet_throttle_configure(tvbuff_t *tvb, proto_tree *command_tree)
{
	proto_tree_add_item(command_tree, hf_throttle_interval, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	proto_tree_add_item(command_tree, hf_throttle_accel, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	proto_tree_add_item(command_tree, hf_throttle_decel, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
}

static void
dissect_enet_connect(tvbuff_t *tvb, proto_tree *command_tree, guint8 verifyConnect)
{
	/* TODO: start conversation between those 2 ENet peers */
	/* TODO: save connected peer IDs to conversation */
	/*conversation_t *conversation = conversation_new(pinfo->fd->num, &pinfo->src, &pinfo->dst, PT_UDP,
									pinfo->srcport, pinfo->dstport, 0);
									*/
	/* Connection parameters */
	proto_tree_add_item(command_tree, hf_con_outgoing_peer_id, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	proto_tree_add_item(command_tree, hf_con_incoming_session_id, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	/* TODO: use ENET_PROTOCOL_HEADER_SESSION_SHIFT and ENET_PROTOCOL_HEADER_SESSION_MASK on session IDs */
	proto_tree_add_item(command_tree, hf_con_outgoing_session_id, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_item(command_tree, hf_con_mtu, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	proto_tree_add_item(command_tree, hf_con_window_size, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	proto_tree_add_item(command_tree, hf_con_channel_count, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	/* Bandwidth, Throttle */
	dissect_enet_bandwidth_limit(tvb, command_tree);
	dissect_enet_throttle_configure(tvb, command_tree);

	proto_tree_add_item(command_tree, hf_con_id, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	if (!verifyConnect)
	{
		proto_tree_add_item(command_tree, hf_con_data, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
	}
}

static void
dissect_enet_disconnect(tvbuff_t *tvb, packet_info *pinfo, proto_tree *command_tree, proto_tree *tree)
{
	/* Disconnect Data */
	const gint remaining = MIN(4, tvb_captured_length_remaining(tvb, offset));
	tvbuff_t *tvb_payload = tvb_new_subset(tvb, offset, remaining, 4);
	proto_tree_add_item(command_tree, hf_disconnect_data, tvb, offset, 4, ENC_BIG_ENDIAN);
	enet_dissect_payload(tvb_payload, pinfo, tree);
	offset += 4;
}

static void
dissect_enet_send_reliable(tvbuff_t *tvb, packet_info *pinfo, proto_tree *command_tree, proto_tree *tree)
{
	tvbuff_t *tvb_payload;
	gint remaining;

	/* Payload length */
	const guint16 payload_length = tvb_get_guint16(tvb, offset, ENC_BIG_ENDIAN);
	proto_tree_add_item(command_tree, hf_payload_length, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	/* Payload */
	proto_tree_add_item(command_tree, hf_payload, tvb, offset, payload_length, ENC_BIG_ENDIAN);
	remaining = MIN(payload_length, tvb_captured_length_remaining(tvb, offset));
	tvb_payload = tvb_new_subset(tvb, offset, remaining, payload_length);
	enet_dissect_payload(tvb_payload, pinfo, tree);
	offset += payload_length;
}

static void
dissect_enet_send_unreliable(tvbuff_t *tvb, packet_info *pinfo, proto_tree *command_tree, proto_tree *tree)
{
	tvbuff_t *tvb_payload;
	gint remaining;
	guint16 payload_length;

	/* Sequence Number */
	proto_tree_add_item(command_tree, hf_unreliable_sequence_number, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	/* Payload length */
	proto_tree_add_item(command_tree, hf_payload_length, tvb, offset, 2, ENC_BIG_ENDIAN);
	payload_length = tvb_get_guint16(tvb, offset, ENC_BIG_ENDIAN);
	offset += 2;

	/* Payload */
	proto_tree_add_item(command_tree, hf_payload, tvb, offset, payload_length, ENC_BIG_ENDIAN);
	remaining = MIN(payload_length, tvb_captured_length_remaining(tvb, offset));
	tvb_payload = tvb_new_subset(tvb, offset, remaining, payload_length);
	enet_dissect_payload(tvb_payload, pinfo, tree);
	offset += hf_payload_length;
}

static void
dissect_enet_send_fragment(tvbuff_t *tvb, packet_info *pinfo, proto_tree *command_tree, proto_tree *tree)
{
	guint16 fragment_start_sequence_number;
	guint16 payload_length;
	guint32 fragment_count;
	guint32 fragment_number;
	guint8 is_last_fragment;
	fragment_head *frag_msg;
	tvbuff_t *tvb_payload = NULL;

	/* Start sequence number (Shared number for all fragments of that payload)*/
	proto_tree_add_item(command_tree, hf_fragment_start_sequence_number, tvb, offset, 2, ENC_BIG_ENDIAN);
	fragment_start_sequence_number = tvb_get_guint16(tvb, offset, ENC_BIG_ENDIAN);
	offset += 2;

	/* Length of the payload in this fragment */
	proto_tree_add_item(command_tree, hf_payload_length, tvb, offset, 2, ENC_BIG_ENDIAN);
	payload_length = tvb_get_guint16(tvb, offset, ENC_BIG_ENDIAN);
	offset += 2;

	/* Number of fragments that make up the payload */
	proto_tree_add_item(command_tree, hf_fragment_count, tvb, offset, 4, ENC_BIG_ENDIAN);
	fragment_count = tvb_get_guint32(tvb, offset, ENC_BIG_ENDIAN);
	offset += 4;

	/* Number of the current fragment, starting with zero */
	proto_tree_add_item(command_tree, hf_fragment_number, tvb, offset, 4, ENC_BIG_ENDIAN);
	fragment_number = tvb_get_guint32(tvb, offset, ENC_BIG_ENDIAN);
	is_last_fragment = fragment_number == fragment_count - 1;
	g_hash_table_contains(table_reassembled_sequenceIDs, GUINT_TO_POINTER(fragment_start_sequence_number));
	offset += 4;

	/* Fragment Total Size (bytes) */
	proto_tree_add_item(command_tree, hf_fragment_total, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	/* Fragment Offset (bytes) */
	proto_tree_add_item(command_tree, hf_fragment_offset, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	/* TODO: if there is a disconnect in between, or if the sequence numbers start again at zero, the table should be reset. */
	/* Also account for different channels, i.e. make a unique value out of (channels, fragment_start_sequence_number) instead of using only (fragment_start_sequence_number) */

	/* TODO: is_last_fragment should not be true if the last fragment was received while others are still missing*/
	frag_msg = fragment_add_seq_check(
		&msg_fragment_table,
		tvb,
		offset,
		pinfo,
		fragment_start_sequence_number,
		NULL,
		fragment_number,
		payload_length,
		!is_last_fragment);

	tvb_payload = process_reassembled_data(
		tvb,
		offset,
		pinfo,
		"Reassembled Message",
		frag_msg,
		&msg_frag_items,
		NULL,
		enet_tree);

	/* Update info column */
	pinfo->fragmented = TRUE;
	if (tvb_payload) {
		g_hash_table_add(table_reassembled_sequenceIDs, GUINT_TO_POINTER(fragment_start_sequence_number));
		col_append_fstr(pinfo->cinfo, COL_INFO, " (%u of %u, Reassembled)", fragment_number + 1, fragment_count);
		enet_dissect_payload(tvb_payload, pinfo, tree);
	} else
		col_append_fstr(pinfo->cinfo, COL_INFO, " (%u of %u)", fragment_number + 1, fragment_count);

	offset += payload_length;
}

static void
dissect_enet_send_unsequenced(tvbuff_t *tvb, packet_info *pinfo, proto_tree *command_tree, proto_tree *tree)
{
	guint16 payload_length;
	tvbuff_t *tvb_payload;
	gint remaining;

	proto_tree_add_item(command_tree, hf_unsequenced_group, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	proto_tree_add_item(command_tree, hf_payload_length, tvb, offset, 2, ENC_BIG_ENDIAN);
	payload_length = tvb_get_guint16(tvb, offset, ENC_BIG_ENDIAN);
	offset += 2;

	proto_tree_add_item(command_tree, hf_payload, tvb, offset, payload_length, ENC_BIG_ENDIAN);
	remaining = MIN(payload_length, tvb_captured_length_remaining(tvb, offset));
	tvb_payload = tvb_new_subset(tvb, offset, remaining, payload_length);
	enet_dissect_payload(tvb_payload, pinfo, tree);
	offset += payload_length;
}

static void
dissect_enet_send_unreliable_fragment(tvbuff_t *tvb, proto_tree *command_tree)
{
	/* TODO: Not supported yet!*/
	proto_tree_add_item(command_tree, hf_payload, tvb, offset, -1, ENC_BIG_ENDIAN);
	offset += tvb_captured_length_remaining(tvb, offset);
}

static void
dissect_enet_count(tvbuff_t *tvb, proto_tree *command_tree)
{
	/* TODO: Not supported yet!*/
	proto_tree_add_item(command_tree, hf_payload, tvb, offset, -1, ENC_BIG_ENDIAN);
	offset += tvb_captured_length_remaining(tvb, offset);
}

static void
dissect_enet_command(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	const guint8 command = tvb_get_guint8(tvb, offset) & ENET_PROTOCOL_COMMAND_MASK;
	const gchar *commandName = val_to_str(command, enet_commands, "Unknown (0x%02x)");
	proto_item *ti = NULL;

	/* Add command subtree */
	proto_tree *command_tree = proto_tree_add_subtree_format(enet_tree, tvb,
			offset, 0, ett_enet_subtree, &ti, "%s", commandName);

	/* Update info column */
	col_append_fstr(pinfo->cinfo, COL_INFO, ", %s" , commandName);

	/* 4 bit command flags + 4 bit command */
	proto_tree_add_item(command_tree, hf_command_acknowledge, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(command_tree, hf_command_unsequenced, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(command_tree, hf_command, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	/* Channel */
	proto_tree_add_item(command_tree, hf_channel, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	/* Sequence number */
	proto_tree_add_item(command_tree, hf_sequence_number, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	/* Dissect command */
	switch(command) {
		case 1: dissect_enet_acknowledge(tvb, command_tree); break;
		case 2: dissect_enet_connect(tvb, command_tree, 0); break;
		case 3: dissect_enet_connect(tvb, command_tree, 1); break;
		case 4: dissect_enet_disconnect(tvb, pinfo, command_tree, tree); break;
		case 5: /* ping */ break;
		case 6: dissect_enet_send_reliable(tvb, pinfo, command_tree, tree); break;
		case 7: dissect_enet_send_unreliable(tvb, pinfo, command_tree, tree); break;
		case 8: dissect_enet_send_fragment(tvb, pinfo, command_tree, tree); break;
		case 9: dissect_enet_send_unsequenced(tvb, pinfo, command_tree, tree); break;
		case 10: dissect_enet_bandwidth_limit(tvb, command_tree); break;
		case 11: dissect_enet_throttle_configure(tvb, command_tree); break;
		case 12: dissect_enet_send_unreliable_fragment(tvb, command_tree); break;
		case 13: dissect_enet_count(tvb, command_tree); break;
		default: break;
	}

	/* Update the reported length of that command */
	proto_item_set_end(ti, tvb, offset);
}

/* Dissects the header of an ENet packet. */
static void
dissect_enet_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	guint8 sentTimeFlag;
	guint16 peerID;

	/* Sent Time & Peer ID*/
	sentTimeFlag = (tvb_get_guint16(tvb, offset, ENC_BIG_ENDIAN) & ENET_PROTOCOL_HEADER_FLAG_SENT_TIME) > 0;
	peerID = tvb_get_guint16(tvb, offset, ENC_BIG_ENDIAN) & ENET_PROTOCOL_MAXIMUM_PEER_ID;

	/* Update info column */
	col_clear(pinfo->cinfo, COL_INFO);
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "ENet");

	/* Add protocol subtree on the second run */
	if (tree) {
		proto_item *ti = proto_tree_add_item(tree, proto_enet, tvb, 0, -1, ENC_NA);
		enet_tree = proto_item_add_subtree(ti, ett_enet_subtree);
	}

	/* Protocol header flags + peerID */
	proto_tree_add_item(enet_tree, hf_flag_sent_time, tvb, offset, 2, ENC_BIG_ENDIAN);
	proto_tree_add_item(enet_tree, hf_flag_compressed, tvb, offset, 2, ENC_BIG_ENDIAN);
	proto_tree_add_item(enet_tree, hf_peer_id, tvb, offset, 2, ENC_BIG_ENDIAN);

	/* Update info column */
	col_add_fstr(pinfo->cinfo, COL_INFO, "PeerID %u", peerID);
	offset += 2;

	/* Optional sent-time */
	if (sentTimeFlag) {
		proto_tree_add_item(enet_tree, hf_sent_time, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;
	}
}

/* Dissects an ENet packet. */
static int
dissect_enet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	const guint16 packet_length = tvb_captured_length(tvb);

	/* Reset the offset since multiple passes are done */
	offset = 0;

	dissect_enet_header(tvb, pinfo, tree);

	while(offset < packet_length)
		dissect_enet_command(tvb, pinfo, tree);

	return offset;
}

static void
setup_dissector(void)
{
	reassembly_table_init(&msg_fragment_table, &addresses_reassembly_table_functions);
	table_reassembled_sequenceIDs = g_hash_table_new(g_direct_hash, g_direct_equal);
}

static void
cleanup_dissector(void)
{
	reassembly_table_destroy(&msg_fragment_table);
	g_hash_table_destroy(table_reassembled_sequenceIDs);
	table_reassembled_sequenceIDs = NULL;
}

void
proto_register_enet(void)
{
	/* Setup protocol subtree array */
	static gint *ett_enet[] = {
		&ett_enet_subtree,
		&ett_msg_fragment_subtree,
		&ett_msg_fragments_subtree
	};

	proto_enet = proto_register_protocol (
		"ENet Protocol",
		"ENet",
		"enet"
	);

	register_dissector("enet", dissect_enet, proto_enet);

	heur_subdissector_list = register_heur_dissector_list("enet", proto_enet);

	proto_register_field_array(proto_enet, hf_enet, array_length(hf_enet));
	proto_register_subtree_array(ett_enet, array_length(ett_enet));

	register_init_routine( setup_dissector );
	register_cleanup_routine( cleanup_dissector );
}

void
proto_reg_handoff_enet(void)
{
	dissector_handle_t handle_enet = create_dissector_handle(dissect_enet, proto_enet);
	dissector_add_for_decode_as("udp.port", handle_enet);

	handle_data = find_dissector("data");
}
