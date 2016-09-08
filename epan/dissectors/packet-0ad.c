/* packet-0ad.c
 *
 * Dissector for the realtime strategy game 0 A.D.
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

/* TODO: typing the following filter produces a crash: 0ad.message_type=="authentication result" and 0ad.authentication_result_code!=1x */
/* TODO: when using the same ett value for each layer, then all items will be expanded, if one is opened: https://ask.wireshark.org/questions/31356/how-to-get-all-tree-items-collapsed-as-default-in-gtk-version */

#include "config.h"

#include <epan/conversation.h>
#include <epan/packet.h>
#include <epan/reassemble.h>

/* The following constants are defined in NetMessages.h */
#define PS_DEFAULT_PORT						0x5073		/* 'P', 's' (UDP Port 20595) */
#define PS_PROTOCOL_MAGIC					0x5073013f	/* 'P', 's', 0x01, '?' */
#define PS_PROTOCOL_MAGIC_RESPONSE			0x50630121	/* 'P', 'c', 0x01, '!' */
#define PS_PROTOCOL_VERSION_PRE_ALPHA_1_2	0x01010002
#define PS_PROTOCOL_VERSION_PRE_ALPHA_3		0x01010003
#define PS_PROTOCOL_VERSION_ALPHA_1_7		0x01010004
#define PS_PROTOCOL_VERSION_ALPHA_8_18		0x01010005
#define PS_PROTOCOL_VERSION_ALPHA_19		0x01010006
#define PS_PROTOCOL_VERSION_ALPHA_20		0x01010011
#define PS_PROTOCOL_VERSION_ALPHA_21		0x01010014

/** This dissector plugin supports 0 A.D. alpha 18 to 21. */
#define GAMEVERSION 21

#if GAMEVERSION == 21
	#define EXPECTED_PROTOCOL_VERSION PS_PROTOCOL_VERSION_ALPHA_21
#elif GAMEVERSION == 20
	#define EXPECTED_PROTOCOL_VERSION PS_PROTOCOL_VERSION_ALPHA_20
#elif GAMEVERSION == 19
	#define EXPECTED_PROTOCOL_VERSION PS_PROTOCOL_VERSION_ALPHA_19
#elif GAMEVERSION >= 8 && GAMEVERSION <= 18
	#define EXPECTED_PROTOCOL_VERSION PS_PROTOCOL_VERSION_ALPHA_8_18
#elif GAMEVERSION >= 1 && GAMEVERSION <= 7
	#define EXPECTED_PROTOCOL_VERSION PS_PROTOCOL_VERSION_ALPHA_1_7
#elif GAMEVERSION >= 1 && GAMEVERSION <= 7
	#define EXPECTED_PROTOCOL_VERSION PS_PROTOCOL_VERSION_ALPHA_1_7
#else
	#define EXPECTED_PROTOCOL_VERSION PS_PROTOCOL_VERSION_PRE_ALPHA_3
#endif

/*
 * Custom serialization used for gamesetup and simulation commands.
 * The following constants are defined in SerializedScriptTypes.h
 */
#define	SCRIPT_TYPE_VOID				0
#define	SCRIPT_TYPE_NULL				1
#define	SCRIPT_TYPE_ARRAY				2
#define	SCRIPT_TYPE_OBJECT				3	/* standard Object prototype */
#define	SCRIPT_TYPE_STRING				4
#define	SCRIPT_TYPE_INT					5
#define	SCRIPT_TYPE_DOUBLE				6
#define	SCRIPT_TYPE_BOOLEAN				7
#define	SCRIPT_TYPE_BACKREF				8
#define	SCRIPT_TYPE_TYPED_ARRAY			9	/* ArrayBufferView subclasses - see below */
#define	SCRIPT_TYPE_ARRAY_BUFFER		10	/* ArrayBuffer containing actual typed array data (may be shared by multiple views) */
#define	SCRIPT_TYPE_OBJECT_PROTOTYPE	11	/* user-defined prototype */
#define	SCRIPT_TYPE_OBJECT_NUMBER		12	/* standard Number class */
#define	SCRIPT_TYPE_OBJECT_STRING		13	/* standard String class */
#define	SCRIPT_TYPE_OBJECT_BOOLEAN		14	/* standard Boolean class */
#define	SCRIPT_TYPE_OBJECT_MAP			15	/* Map class */
#define	SCRIPT_TYPE_OBJECT_SET			16	/* Set class */

static const value_string ScriptTypes[] = {
	{ SCRIPT_TYPE_VOID, "Void" },
	{ SCRIPT_TYPE_NULL, "NULL" },
	{ SCRIPT_TYPE_ARRAY, "Array" },
	{ SCRIPT_TYPE_OBJECT, "Object" },
	{ SCRIPT_TYPE_STRING, "String" },
	{ SCRIPT_TYPE_INT, "Integer" },
	{ SCRIPT_TYPE_DOUBLE, "Double" },
	{ SCRIPT_TYPE_BOOLEAN, "Boolean" },
	{ SCRIPT_TYPE_BACKREF, "Backref" },
	{ SCRIPT_TYPE_TYPED_ARRAY, "Typed Array" },
	{ SCRIPT_TYPE_ARRAY_BUFFER, "Array Buffer" },
	{ SCRIPT_TYPE_OBJECT_PROTOTYPE, "Object Prototype" },
	{ SCRIPT_TYPE_OBJECT_NUMBER, "Object Number" },
	{ SCRIPT_TYPE_OBJECT_STRING, "Object String" },
	{ SCRIPT_TYPE_OBJECT_BOOLEAN, "Object Boolean" },
	{ SCRIPT_TYPE_OBJECT_MAP, "Object Map" },
	{ SCRIPT_TYPE_OBJECT_SET, "Object Set" }
};
// ArrayBufferView subclasses (to avoid relying directly on the JSAPI enums)
/*enum
{
	SCRIPT_TYPED_ARRAY_INT8 = 0,
	SCRIPT_TYPED_ARRAY_UINT8 = 1,
	SCRIPT_TYPED_ARRAY_INT16 = 2,
	SCRIPT_TYPED_ARRAY_UINT16 = 3,
	SCRIPT_TYPED_ARRAY_INT32 = 4,
	SCRIPT_TYPED_ARRAY_UINT32 = 5,
	SCRIPT_TYPED_ARRAY_FLOAT32 = 6,
	SCRIPT_TYPED_ARRAY_FLOAT64 = 7,
	SCRIPT_TYPED_ARRAY_UINT8_CLAMPED = 8
};*/

/* The protocol version has changed only a few times. */
static const value_string ProtocolVersion[] = {
	{ PS_PROTOCOL_VERSION_PRE_ALPHA_1_2, "Pre-Alpha 1 or 2" },
	{ PS_PROTOCOL_VERSION_PRE_ALPHA_3, "Pre-Alpha 3" },
	{ PS_PROTOCOL_VERSION_ALPHA_1_7, "Alpha 1 to 7" },
	{ PS_PROTOCOL_VERSION_ALPHA_8_18, "Alpha 8 to 18" },
	{ PS_PROTOCOL_VERSION_ALPHA_19, "Alpha 19" },
	{ PS_PROTOCOL_VERSION_ALPHA_20, "Alpha 20" },
	{ PS_PROTOCOL_VERSION_ALPHA_21, "Alpha 21" },
	{ 0, NULL }
};

/* As of alpha 19, the protocol magic is the same for all version of the protocol. */
static const value_string ProtocolMagic[] = {
	{ PS_PROTOCOL_MAGIC, "Protocol Magic (Server)" },
	{ PS_PROTOCOL_MAGIC_RESPONSE, "Protocol Magic (Client)" },
	{ 0, NULL }
};

/* Offset to avoid duplicate entries */
#if GAMEVERSION >= 21
#define COMMAND_OFFSET1 1
#define COMMAND_OFFSET2 2
#else
#define COMMAND_OFFSET1 0
#define COMMAND_OFFSET2 0
#endif

#if GAMEVERSION <= 18
#define COMMAND_OFFSET4 0
#elif GAMEVERSION == 19
#define COMMAND_OFFSET4 2
#elif GAMEVERSION == 20
#define COMMAND_OFFSET4 4
#else
#define COMMAND_OFFSET4 5
#endif

#define COMMAND_OFFSET3 COMMAND_OFFSET2+COMMAND_OFFSET4


static const value_string NetMessageTypes[] = {
	{ 0, "Invalid" },
	{ 1, "Server Handshake" },
	{ 2, "Client Handshake" },
	{ 3, "Server Handshake Response" },
	{ 4, "Authentication" },
	{ 5, "Authentication Result" },
	{ 6, "Chat" },
	{ 7, "Ready" },
#if GAMEVERSION >= 21
	{ 8, "Clear Ready" },
#endif
	{ 8 + COMMAND_OFFSET1, "Game Setup" },
#if GAMEVERSION >= 21
	{ 9 + COMMAND_OFFSET1, "Player Assignment Request" },
#endif
	{ 9 + COMMAND_OFFSET2, "Player Assignments" },
	{ 10 + COMMAND_OFFSET2, "File Transfer Request" },
	{ 11 + COMMAND_OFFSET2, "File Transfer Response" },
	{ 12 + COMMAND_OFFSET2, "File Transfer Data" },
	{ 13 + COMMAND_OFFSET2, "File Transfer Acknowledge" },
	{ 14 + COMMAND_OFFSET2, "Join Sync Start" },
#if GAMEVERSION >= 19
	{ 15 + COMMAND_OFFSET2, "Client Rejoined" },
	{ 16 + COMMAND_OFFSET2, "Client Kicked" },
#endif
#if GAMEVERSION >= 20
	{ 17 + COMMAND_OFFSET2, "Client Timeout" },
	{ 18 + COMMAND_OFFSET2, "Client Performance" },
#endif
#if GAMEVERSION >= 21
	{ 19 + COMMAND_OFFSET2, "Client Paused" },
#endif
	{ 15 + COMMAND_OFFSET3, "Loaded Game" },
	{ 16 + COMMAND_OFFSET3, "Game Start" },
	{ 17 + COMMAND_OFFSET3, "End Command Batch"},
	{ 18 + COMMAND_OFFSET3, "Synchronization Check"},
	{ 19 + COMMAND_OFFSET3, "Synchronization Error"},
	{ 20 + COMMAND_OFFSET3, "Simulation Command"},
	{ 21 + COMMAND_OFFSET3, NULL }
};

static const value_string AuthenticationResult[] = {
	{ 0, "Ok" },
	{ 1, "Rejoining" },
	{ 2, "Invalid Password" }
};

/* This has never changed. */
static const value_string ReadyStatus[] = {
	{ 0, "Not Ready" },
	{ 1, "Ready" }
};

/* Taken from NetHost.h */
static const value_string DisconnectReason[] = {
	{ 0, "Unknown" },
	{ 1, "Host Quit" },
	{ 2, "Incorrect Protocol Version" },

#if GAMEVERSION == 18
	{ 3, "Game has started already" }
#elif GAMEVERSION >= 19
	{ 3, "Game loading" },
	{ 4, "Game has started already" },
	{ 5, "Kicked" },
	{ 6, "Banned" },
#endif

#if GAMEVERSION >= 20
	{ 7, "Playername in use" },
	{ 8, "Server full" }
#endif
};

static dissector_handle_t handle_0ad = NULL;
static reassembly_table msg_fragment_table;

GHashTable *table_guid_username = NULL;
GHashTable *table_packetNr = NULL;
GHashTable *table_totalSize = NULL;
GHashTable *table_fileSize = NULL;

static int proto_0ad = -1;
static int offset = 0;

static proto_tree *tree_0ad = NULL;
static gint ett_0ad_subtree = -1;
static gint ett_0ad_script_array_subtree = -1;
static gint ett_0ad_player_assignment_subtree = -1;
static gint ett_msg_fragment_subtree = -1;
static gint ett_msg_fragments_subtree = -1;

static gint hf_script_type = -1;
static gint hf_script_integer = -1;
static gint hf_script_bool = -1;
static gint hf_script_string = -1;

static gint hf_message_type = -1;
static gint hf_serialized_data_length = -1;

static gint hf_protocol_magic = -1;
static gint hf_protocol_version = -1;
static gint hf_software_version = -1;

static gint hf_connection_flags = -1;
static gint hf_connection_message = -1;

static gint hf_disconnect_reason = -1;

static gint hf_user_guid_length = -1;
static gint hf_user_guid = -1;
static gint hf_username = -1;
static gint hf_player_id = -1;
static gint hf_authentication_password = -1;

static gint hf_host_id = -1;
static gint hf_authentication_result_code = -1;
static gint hf_authentication_result_message = -1;

static gint hf_chat_message = -1;
static gint hf_ready_status = -1;

#if GAMEVERSION >= 19
static gint hf_ban_flag = -1;
#endif

#if GAMEVERSION >= 20
static gint hf_last_received_time = -1;
static gint hf_mean_rtt = -1;
#endif

#if GAMEVERSION >= 21
static gint hf_pause_flag = -1;
#endif

static gint hf_current_turn = -1;
static gint hf_turn_length = -1;
static gint hf_hash = -1;
static gint hf_hash_length = -1;

static gint hf_file_transfer_request_id = -1;
static gint hf_file_transfer_length = -1;
static gint hf_file_transfer_data = -1;
static gint hf_file_transfer_number_of_packets = -1;

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

/* See https://www.wireshark.org/docs/wsar_html/epan/struct__header__field__info.html */
static hf_register_info hf[] = {
	{ &hf_message_type,
		{ "Message Type", "0ad.message_type",
		FT_UINT8, BASE_DEC,
		VALS(NetMessageTypes), 0x0,
		"Message type of that packet.", HFILL }
	},
	{ &hf_script_type,
		{ "Field Type", "0ad.script_type",
		FT_UINT8, BASE_DEC,
		VALS(ScriptTypes), 0x0,
		"Type of that element.", HFILL }
	},
	{ &hf_script_integer,
		{ "Integer", "0ad.script_integer",
		FT_UINT32, BASE_DEC,
		NULL, 0x0,
		"A 32bit number.", HFILL }
	},
	{ &hf_script_bool,
		{ "Boolean", "0ad.script_boolean",
		FT_UINT8, BASE_DEC,
		"NULL", 0x0,
		"True or false.", HFILL }
	},
	{ &hf_script_string,
		{ "String", "0ad.script_string",
		FT_STRING, BASE_NONE,
		NULL, 0x0,
		"An element containing text.", HFILL }
	},
	{ &hf_serialized_data_length,
		{ "Serialized Data Length", "0ad.serialization_data_length",
		FT_UINT16, BASE_DEC,
		NULL, 0x0,
		"Number of bytes of the serialized data (which includes the message type and this field too).", HFILL }
	},
	{ &hf_protocol_magic,
		{ "Protocol Magic", "0ad.protocol_magic",
		FT_UINT32, BASE_HEX,
		VALS(ProtocolMagic), 0x0,
		"Some magic value, probably arbitrary.", HFILL }
	},
	{ &hf_protocol_version,
		{ "Protocol Version", "0ad.protocol_version",
		FT_UINT32, BASE_HEX,
		VALS(ProtocolVersion), 0x0,
		"Sequential value that is increased with each network protocol change.", HFILL }
	},
	{ &hf_software_version,
		{ "Software Version", "0ad.software_version",
		FT_UINT32, BASE_HEX,
		VALS(ProtocolVersion), 0x0,
		"Currently identical to the protocol version.", HFILL }
	},
	{ &hf_connection_flags,
		{ "Flags", "0ad.connection_flags",
		FT_UINT32, BASE_HEX,
		NULL, 0x0,
		"No flags have been defined for now, so the value is always zero.", HFILL }
	},
	{ &hf_connection_message,
		{ "Connect Message", "0ad.connection_message",
		FT_NONE, BASE_NONE,
		NULL, 0x0,
		"A text message that is sent on connect, currently it is always 'Welcome'.", HFILL }
	},
	{ &hf_disconnect_reason,
		{ "Disconnect Reason", "0ad.disconnect_reason",
		FT_UINT32, BASE_HEX,
		VALS(DisconnectReason), 0x0,
		"The reason why the connection endet.", HFILL }
	},
	{ &hf_user_guid_length,
		{ "User GUID Length", "0ad.user_guid_length",
		FT_UINT32, BASE_DEC,
		NULL, 0x0,
		"Number of bytes of the GUID of that user.", HFILL }
	},
	{ &hf_user_guid,
		{ "User GUID", "0ad.user_guid",
		FT_STRING, BASE_NONE,
		NULL, 0x0,
		"A globally unique hexadecimal value that identifies the user.", HFILL }
	},
	{ &hf_player_id,
		{ "Player ID", "0ad.player_id",
		FT_INT8, BASE_DEC,
		NULL, 0x0,
		"Sequential index of that player. Gaia has 0 and observers -1.", HFILL }
	},
	{ &hf_username,
		{ "Username", "0ad.username",
		FT_NONE, BASE_NONE,
		NULL, 0x0,
		"The chosen name of the player (or observer).", HFILL }
	},
	{ &hf_authentication_password,
		{ "Password", "0ad.password",
		FT_NONE, BASE_NONE,
		NULL, 0x0,
		"The password used to login to the server.", HFILL }
	},
	{ &hf_authentication_result_code,
		{ "Authentication Result Code", "0ad.authentication_result_code",
		FT_UINT32, BASE_HEX,
		VALS(AuthenticationResult), 0x0,
		"The result of the authentication in a machine-readable form.", HFILL }
	},
	{ &hf_authentication_result_message,
		{ "Authentication Result Message", "0ad.authentication_result_message",
		FT_NONE, BASE_NONE,
		NULL, 0x0,
		"The result of the authentication in a human-readable form.", HFILL }
	},
	{ &hf_host_id,
		{ "Host ID", "0ad.host_id",
		FT_UINT16, BASE_DEC,
		NULL, 0x0,
		"A sequential number identifying the peer, beginning with 1.", HFILL }
	},
	{ &hf_chat_message,
		{ "Chat Message", "0ad.chat",
		FT_NONE, BASE_NONE,
		NULL, 0x0,
		"The chat message that the user sent.", HFILL }
	},
#if GAMEVERSION >= 19
	{ &hf_ban_flag,
		{ "Ban Flag", "0ad.ban",
		FT_BOOLEAN, 0,
		NULL, 0x0,
		"Whether the client was banned.", HFILL }
	},
#endif
#if GAMEVERSION >= 20
	{ &hf_last_received_time,
		{ "Last Received", "0ad.last_received",
		FT_UINT32, BASE_DEC,
		NULL, 0x0,
		"Unix timestamp stating when the server received the last packet from that client.", HFILL }
	},
	{ &hf_mean_rtt,
		{ "Last Received", "0ad.mean_rtt",
		FT_UINT32, BASE_DEC,
		NULL, 0x0,
		"Mean round trip time between the server and that client in milliseconds.", HFILL }
	},
#endif
#if GAMEVERSION >= 21
	{ &hf_pause_flag,
		{ "Paused", "0ad.paused",
		FT_BOOLEAN, 0,
		NULL, 0x0,
		"Whether that client has paused or unpaused the game.", HFILL }
	},
#endif
	{ &hf_ready_status,
		{ "Ready Status", "0ad.ready_status",
		FT_UINT8, BASE_DEC,
		VALS(ReadyStatus), 0x0,
		"Whether or not the user is ready.", HFILL }
	},
	{ &hf_current_turn,
		{ "Current Turn", "0ad.current_turn",
		FT_UINT32, BASE_DEC,
		NULL, 0x0,
		"A sequential number identifying the current turn.", HFILL }
	},
	{ &hf_turn_length,
		{ "Turn Length", "0ad.turn_length",
		FT_UINT16, BASE_DEC,
		NULL, 0x0,
		"The number of milliseconds that this turn lasted.", HFILL }
	},
	{ &hf_hash,
		{ "Simulation Hash", "0ad.simulation_hash",
		FT_BYTES, BASE_NONE,
		NULL, 0x0,
		"A hash of the games current simulation state, used for synchronization check.", HFILL }
	},
	{ &hf_hash_length,
		{ "Simulation Hash Length", "0ad.simulation_hash_length",
		FT_UINT32, BASE_DEC,
		NULL, 0x0,
		"The length of the hash value.", HFILL }
	},
	{ &hf_file_transfer_request_id,
		{ "File Transfer Request ID", "0ad.file_transfer.request_id",
		FT_UINT32, BASE_DEC,
		NULL, 0x0,
		"A sequential, unique number identifying the current file transfer.", HFILL }
	},
	{ &hf_file_transfer_length,
		{ "File Transfer Size", "0ad.file_transfer.total_size",
		FT_UINT32, BASE_DEC,
		NULL, 0x0,
		"The size of the file to be transfered.", HFILL }
	},
	{ &hf_file_transfer_data,
		{ "File Transfer Data", "0ad.file_transfer.data",
		FT_NONE, BASE_NONE,
		NULL, 0x0,
		"The part of the file that was sent in this message.", HFILL }
	},
	{ &hf_file_transfer_number_of_packets,
		{ "File Transfer Acknowledged Packets", "0ad.file_transfer.packet_count",
		FT_UINT8, BASE_DEC,
		NULL, 0x0,
		"The number of fragments that were acknowledged with this message. Currently always 1.", HFILL } /* TODO */
	},
	{ &hf_msg_fragments,
		{ "Message fragments", "0ad.fragments",
		FT_BYTES, BASE_NONE,
		NULL, 0x00,
		NULL, HFILL }
	},
	{ &hf_msg_fragment,
		{ "Message fragment", "0ad.fragment",
		FT_FRAMENUM, BASE_NONE,
		NULL, 0x00,
		NULL, HFILL }
	},
	{ &hf_msg_fragment_overlap,
		{ "Message fragment overlap", "0ad.fragment.overlap",
		FT_BOOLEAN, 0,
		NULL, 0x00,
		NULL, HFILL }
	},
	{ &hf_msg_fragment_overlap_conflicts,
		{ "Message fragment overlapping with conflicting data", "0ad.fragment.overlap.conflicts",
		FT_BOOLEAN, 0,
		NULL, 0x00,
		NULL, HFILL }
	},
	{ &hf_msg_fragment_multiple_tails,
		{ "Message has multiple tail fragments", "0ad.fragment.multiple_tails",
		FT_BOOLEAN, 0,
		NULL, 0x00,
		NULL, HFILL }
	},
	{ &hf_msg_fragment_too_long_fragment,
		{ "Message fragment too long", "0ad.fragment.too_long_fragment",
		FT_BOOLEAN, 0,
		NULL, 0x00,
		NULL, HFILL }
	},
	{ &hf_msg_fragment_error,
		{ "Message defragmentation error", "0ad.fragment.error",
		FT_FRAMENUM, BASE_NONE,
		NULL, 0x00,
		NULL, HFILL }
	},
	{ &hf_msg_fragment_count,
		{ "Message fragment count", "0ad.fragment.count",
		FT_UINT32, BASE_DEC,
		NULL, 0x00,
		NULL, HFILL }
	},
	{ &hf_msg_reassembled_in,
		{ "Reassembled in", "0ad.file_transfer.reassembled.in",
		FT_FRAMENUM, BASE_NONE,
		NULL, 0x00,
		NULL, HFILL }
	},
	{ &hf_msg_reassembled_length,
		{ "Reassembled length", "0ad.file_transfer.reassembled.length",
		FT_UINT32, BASE_DEC,
		NULL, 0x00,
		NULL, HFILL }
	},
	{ &hf_msg_reassembled_data,
		{ "Reassembled data", "0ad.file_transfer.reassembled.data",
		FT_NONE, BASE_NONE,
		NULL, 0x00,
		NULL, HFILL }
	}
};

/* First some commonly used string parsing methods. */

/* Parses an UTF-8 string. */
static gchar*
dissect_0ad_string(tvbuff_t *tvb, gint hf_string_length, gint hf_string, proto_tree *tree)
{
	gchar *string;

	/* String Length */
	const guint32 string_length = tvb_get_guint32(tvb, offset, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_string_length, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	/* String */
	string = tvb_get_string_enc(wmem_packet_scope(), tvb, offset, string_length, ENC_UTF_8);
	proto_tree_add_item(tree, hf_string, tvb, offset, string_length, ENC_BIG_ENDIAN);
	offset += string_length;

	return string;
}

/* Get length of next UTF-16 string. */
static int
get_wide_string_length(tvbuff_t *tvb, guint encoding)
{
	guint16 wchar;
	int i = 0;

	/* Return offset of the next null-termination */
	do {
		wchar = tvb_get_guint16(tvb, offset + i, encoding);
		i += 2;
	} while(wchar != 0);

	return i;
}

/* Get next UTF-16 string. */
static gchar*
dissect_0ad_wide_string(tvbuff_t *tvb, gint hf_string, proto_tree *tree, guint encoding)
{
	/* String Length*/
	const int string_length = get_wide_string_length(tvb, encoding);

	/* String */
	gchar *string = tvb_get_string_enc(wmem_packet_scope(), tvb, offset, string_length, ENC_UTF_16|encoding);

	/* Add Item */
	proto_item *dataItem = proto_tree_add_item(tree, hf_string, tvb, offset, string_length, encoding);
	proto_item_append_text(dataItem, ": %s", string);

	offset += string_length;
	return string;
}

/* Registers a new arbitrary element. */
/*static void register_0ad_script_element(int *p_id, const guint type, const gchar *parent_field, const gchar *fieldname)
{
	static int hf_id;
	hf_register_info hfri;
	hfri.p_id				= &hf_id;
	hfri.hfinfo.name		= fieldname;
	hfri.hfinfo.abbrev		= g_strdup_printf("%s.%s", parent_field, g_utf8_strdown(fieldname, strlen(fieldname)));
	switch(type) {
		case SCRIPT_TYPE_STRING: hfri.hfinfo.type = FT_STRING; hfri.hfinfo.display = BASE_NONE; break;
		case SCRIPT_TYPE_INT:	hfri.hfinfo.type = FT_UINT32; hfri.hfinfo.display = BASE_DEC; break;
		case SCRIPT_TYPE_BOOLEAN: hfri.hfinfo.type = FT_UINT8; hfri.hfinfo.display = BASE_HEX; break;
		default: break;
	}
	hfri.hfinfo.strings		= NULL;
	hfri.hfinfo.bitmask		= 0x0;
	hfri.hfinfo.blurb		= NULL;
	hfri.hfinfo.id			= 0;
	hfri.hfinfo.parent		= 0;
	hfri.hfinfo.ref_type	= HF_REF_TYPE_NONE;
	hfri.hfinfo.same_name_next = NULL;
	hfri.hfinfo.same_name_prev_id = -1;

	wmem_array_append_one(hf, hfri);
}*/

/* Script parsing functions */
static guint32
dissect_0ad_script_integer(tvbuff_t *tvb, const gchar *fieldname, proto_tree *tree, guint encoding)
{
	const guint32 value = tvb_get_guint32(tvb, offset, encoding);
	proto_item *ti = proto_tree_add_item(tree, hf_script_integer, tvb, offset, 4, encoding);
	proto_item_set_text(ti, "%s: %u", fieldname, value);
	offset += 4;
	return value;
}

static gboolean
dissect_0ad_script_boolean(tvbuff_t *tvb, const gchar *fieldname, proto_tree *tree, guint encoding)
{
	const gboolean value = (gboolean) tvb_get_guint8(tvb, offset);
	proto_item *ti = proto_tree_add_item(tree, hf_script_bool, tvb, offset, 1, encoding);
	proto_item_set_text(ti, "%s: %s", fieldname, value ? "True" : "False");
	offset += 1;
	return value;
}

static gchar*
dissect_0ad_script_string(tvbuff_t *tvb, const gchar *fieldname, proto_tree *tree, guint encoding)
{
	/* Add subtree */
	proto_item *ti = NULL;
	proto_tree *subtree = proto_tree_add_subtree(tree, tvb,
			offset, 0, ett_0ad_script_array_subtree, &ti, "");

	/* String Length */
	guint32 string_length = 2 * dissect_0ad_script_integer(tvb, g_strdup_printf("Length"), subtree, encoding);

	/* String */
	gchar *string = tvb_get_string_enc(wmem_packet_scope(), tvb, offset, string_length, ENC_UTF_16|encoding);

	proto_tree_add_item(subtree, hf_script_string, tvb, offset, string_length, ENC_UTF_16|encoding);
	proto_item_set_text(ti, "%s: %s", fieldname, string);
	offset += string_length;

	/* Update reported length */
	proto_item_set_end(subtree, tvb, offset);

	return string;
}

static void
dissect_0ad_script_element(tvbuff_t *tvb, const gchar *parent_field, const gchar *fieldname, proto_tree *tree, guint encoding);

/* Recursively parse array or object. */
static void
dissect_0ad_script_array(tvbuff_t *tvb, const gchar *parent_field, const gchar *fieldname, guint8 type, proto_tree *tree, guint encoding)
{
	/* TODO: Create subtree */
	/*const gchar *type_name = val_to_str(type, ScriptTypes, "Unknown (0x%02x)");*/
	proto_item *ti = NULL;
	proto_tree *tree_array = proto_tree_add_subtree(tree, tvb,
			offset, 0, ett_0ad_script_array_subtree, &ti, fieldname);

	/* Number of items + dupe */
	const guint32 number_of_items = dissect_0ad_script_integer(tvb, "Number of items", tree_array, encoding);
	guint32 i;

	/* For arrays the number of items is repeated TODO: why? */
	if (type == SCRIPT_TYPE_ARRAY)
		dissect_0ad_script_integer(tvb, "Number of items", tree_array, encoding);

	/* Loop over items */
	for(i = 0; i < number_of_items; ++i) {

		/* Key */
		gchar *key = dissect_0ad_script_string(tvb, "Field Name", tree_array, encoding);

		/* Register an element for each item of that array / object */
		/*register_0ad_script_element(type, parent_field, key);*/

		/* Value */
		dissect_0ad_script_element(tvb, parent_field, key, tree_array, encoding);
	}

	/* Update reported length */
	proto_item_set_end(tree_array, tvb, offset);
}

/* Wrapper that recursively parses an arbitrary element. */
static void
dissect_0ad_script_element(tvbuff_t *tvb, const gchar *parent_field, const gchar *fieldname, proto_tree *tree, guint encoding)
{
	/* Type */
	const guint8 type = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(tree, hf_script_type, tvb, offset, 1, encoding);
	offset += 1;

	/* Value */
	switch(type)
	{
		case SCRIPT_TYPE_ARRAY: dissect_0ad_script_array(tvb, parent_field, fieldname, type, tree, encoding); break;
		case SCRIPT_TYPE_OBJECT: dissect_0ad_script_array(tvb, parent_field, fieldname, type, tree, encoding); break;
		case SCRIPT_TYPE_STRING: dissect_0ad_script_string(tvb, fieldname, tree, encoding); break;
		case SCRIPT_TYPE_INT: dissect_0ad_script_integer(tvb, fieldname, tree, encoding); break;
		case SCRIPT_TYPE_BOOLEAN: dissect_0ad_script_boolean(tvb, fieldname, tree, encoding); break;
		default: break;//g_print("NOT SUPPORTED"); /* TODO: throw not supported error */ break;
	}
}

/* Parsing of 0 A.D. messages that utilize the methods above */

static void
dissect_0ad_protocol_version(tvbuff_t *tvb, packet_info *pinfo)
{
	guint32 protocol_version = tvb_get_guint32(tvb, offset, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree_0ad, hf_protocol_version, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	if (protocol_version != EXPECTED_PROTOCOL_VERSION) {
		col_clear(pinfo->cinfo,COL_INFO);
		col_append_fstr(
			pinfo->cinfo,
			COL_INFO,
			"Wrong protocol version, found %#010x, expected %#010x (alpha %d).",
			protocol_version,
			EXPECTED_PROTOCOL_VERSION,
			GAMEVERSION);
	}
}

static void
dissect_0ad_handshake(tvbuff_t *tvb, packet_info *pinfo)
{
	/* Protocol Magic */
	proto_tree_add_item(tree_0ad, hf_protocol_magic, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	/* Protocol Version */
	dissect_0ad_protocol_version(tvb, pinfo);

	/* Software Version */
	proto_tree_add_item(tree_0ad, hf_software_version, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

}

static void
dissect_0ad_server_handshake_response(tvbuff_t *tvb, packet_info *pinfo)
{
	/* Protocol Version */
	dissect_0ad_protocol_version(tvb, pinfo);

	/* Flags */
	proto_tree_add_item(tree_0ad, hf_connection_flags, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	/* Welcome Message */
	dissect_0ad_wide_string(tvb, hf_connection_message, tree_0ad, ENC_BIG_ENDIAN);
}

static void
dissect_0ad_authentication(tvbuff_t *tvb)
{
	/* User GUID */
	dissect_0ad_string(tvb, hf_user_guid_length, hf_user_guid, tree_0ad);

	/* Username */
	dissect_0ad_wide_string(tvb, hf_username, tree_0ad, ENC_BIG_ENDIAN);

	/* Password */
	dissect_0ad_wide_string(tvb, hf_authentication_password, tree_0ad, ENC_BIG_ENDIAN);
}

static void
dissect_0ad_authentication_result(tvbuff_t *tvb)
{
	/* Result Code*/
	proto_tree_add_item(tree_0ad, hf_authentication_result_code, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	/* Host ID */
	proto_tree_add_item(tree_0ad, hf_host_id, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	/* Result Message (currently always "Logged In") */
	dissect_0ad_wide_string(tvb, hf_authentication_result_message, tree_0ad, ENC_BIG_ENDIAN);
}

static void
dissect_0ad_chat(tvbuff_t *tvb, packet_info *pinfo)
{
	/* TODO: Differentiate incoming and outgoing chat messages */
	/* In the latter case the GUID is null */

	/* User GUID */
	const gchar *user_guid = dissect_0ad_string(tvb, hf_user_guid_length, hf_user_guid, tree_0ad);
	const gchar *username = (const gchar*) g_hash_table_lookup(table_guid_username, (gpointer) g_strdup(user_guid));

	/* Chat Message */
	const gchar *text = dissect_0ad_wide_string(tvb, hf_chat_message, tree_0ad, ENC_BIG_ENDIAN);

	/* Update colum info */
	if (strlen(user_guid) > 0)
		col_append_fstr(pinfo->cinfo, COL_INFO, " %s: %s", username, text);
}

static void
dissect_0ad_ready(tvbuff_t *tvb, packet_info *pinfo)
{
	/* User GUID */
	const gchar *user_guid = dissect_0ad_string(tvb, hf_user_guid_length, hf_user_guid, tree_0ad);
	const gchar *username = (const gchar*) g_hash_table_lookup(table_guid_username, (gpointer) g_strdup(user_guid));

	/* Ready Status */
	const guint8 readyStatus = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(tree_0ad, hf_ready_status, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	/* Update column info with playernames */
	if (strlen(user_guid) > 0) {
		if (readyStatus)
			col_append_fstr(pinfo->cinfo, COL_INFO, " %s", username);
		else
			col_append_fstr(pinfo->cinfo, COL_INFO, " %s (not ready)", username);
	} else if(!readyStatus)
		col_append_str(pinfo->cinfo, COL_INFO, " (not ready)");

	/* TODO: show column info (name + ready state)*/
}

static void
dissect_0ad_gamesetup(tvbuff_t *tvb, proto_item *tree_item_0ad)
{
	dissect_0ad_script_element(tvb, "0ad", "Gamesetup", tree_item_0ad, ENC_LITTLE_ENDIAN);
}

#if GAMEVERSION >= 21
static void
dissect_0ad_player_assignment_request(tvbuff_t *tvb, packet_info *pinfo)
{
	const gchar *user_guid;
	const gchar *username;

	/* Player ID */
	const gint8 playerID = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(tree_0ad, hf_player_id, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	/* User GUID */
	user_guid = dissect_0ad_string(tvb, hf_user_guid_length, hf_user_guid, tree_0ad);
	username = (const gchar*) g_hash_table_lookup(table_guid_username, (gpointer) g_strdup(user_guid));

	/* Update colum info */
	if (strlen(user_guid) > 0)
		col_append_fstr(pinfo->cinfo, COL_INFO, ": %s -> %d", username, playerID);
}
#endif

static void
dissect_0ad_player_assignments(tvbuff_t *tvb, packet_info *pinfo)
{
	/* TODO: maybe the assignemnt can be empty? */
	gint8 playerID;
	proto_item *ti = NULL;
	gchar *user_guid;
	gchar *username;

	do {
		/* Player Assignment Tree */
		proto_tree *tree_player_assignment = proto_tree_add_subtree(tree_0ad, tvb,
				offset, 0, ett_0ad_player_assignment_subtree, &ti, "Player Assignment");

		/* User GUID */
		user_guid = dissect_0ad_string(tvb, hf_user_guid_length, hf_user_guid, tree_player_assignment);

		/* Username */
		username = dissect_0ad_wide_string(tvb, hf_username, tree_player_assignment, ENC_BIG_ENDIAN);

		/* TODO: check that it is linked to the conversation */
		/* TODO: should be removed when disconnected */
		g_hash_table_replace(table_guid_username, (gpointer)g_strdup(user_guid), (gpointer)g_strdup(username));

		/* Player ID */
		playerID = tvb_get_guint8(tvb, offset);
		proto_tree_add_item(tree_player_assignment, hf_player_id, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset += 1;

		/* Ready Status */
		proto_tree_add_item(tree_player_assignment, hf_ready_status, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset += 1;

		/* Update reported length */
		proto_item_set_end(tree_player_assignment, tvb, offset);

		/* Update text */
		proto_item_set_text(ti, "Player Assignment (Player %u: %s)", playerID, username);

		/* Update column info with playernames */
		col_append_fstr(pinfo->cinfo, COL_INFO, " %u: %s", playerID, username);

	} while(tvb_captured_length_remaining(tvb, offset) > 0);
}

static void
dissect_0ad_file_transfer_request(tvbuff_t *tvb)
{
	/* Request ID */
	proto_tree_add_item(tree_0ad, hf_file_transfer_request_id, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
}

static void
dissect_0ad_file_transfer_response(tvbuff_t *tvb)
{
	guint32 fileSize;

	/* Request ID*/
	const guint32 requestID = tvb_get_guint32(tvb, offset, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree_0ad, hf_file_transfer_request_id, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	/* Total File Size */
	fileSize = tvb_get_guint32(tvb, offset, ENC_BIG_ENDIAN);
	g_hash_table_replace(table_fileSize, GUINT_TO_POINTER(requestID), GUINT_TO_POINTER((guint) 0));
	g_hash_table_replace(table_totalSize, GUINT_TO_POINTER(requestID), GUINT_TO_POINTER((guint) fileSize));
	proto_tree_add_item(tree_0ad, hf_file_transfer_length, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
}

static void
dissect_0ad_file_transfer_data(tvbuff_t *tvb, packet_info *pinfo)
{
	gint dataLength;
	fragment_head *frag_msg;
	tvbuff_t *tvb_payload;
	guint packetNumber, currentSize, totalSize;

	/* TODO: can two clients have the same requestID ? If so, the hash table is broken */

	/* Request ID*/
	const guint32 requestID = tvb_get_guint32(tvb, offset, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree_0ad, hf_file_transfer_request_id, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	/* Data */
	dataLength = tvb_captured_length_remaining(tvb, offset);
	proto_tree_add_item(tree_0ad, hf_file_transfer_data, tvb, offset, dataLength, ENC_BIG_ENDIAN);

	/* Load Total File Size */
	totalSize = GPOINTER_TO_UINT(g_hash_table_lookup(table_totalSize, GUINT_TO_POINTER(requestID)));

	/* Compute Current File Size */
	currentSize = dataLength + GPOINTER_TO_UINT(g_hash_table_lookup(table_fileSize, GUINT_TO_POINTER(requestID)));
	g_hash_table_replace(table_fileSize, GUINT_TO_POINTER(requestID), GUINT_TO_POINTER((guint) currentSize));

	/* Compute Fragment Number */
	packetNumber = GPOINTER_TO_UINT(g_hash_table_lookup(table_packetNr, GUINT_TO_POINTER(requestID)));
	g_hash_table_replace(table_packetNr, GUINT_TO_POINTER(requestID), GUINT_TO_POINTER((guint) packetNumber + 1));

	/* Reassemble fragments */
	frag_msg = fragment_add_seq_check(
		&msg_fragment_table,
		tvb,
		offset,
		pinfo,
		requestID,
		NULL,
		packetNumber,
		dataLength,
		currentSize < totalSize);

	tvb_payload = process_reassembled_data(
		tvb,
		offset,
		pinfo,
		"Reassembled Message",
		frag_msg,
		&msg_frag_items,
		NULL,
		tree_0ad);

	if (!tvb_payload)
		tvb_payload = tvb_new_subset(tvb, offset, dataLength, dataLength);

	/* TODO: packetnumber seems wrong, doesn't reset to zero on second pass, save it in the packet info */

	/* Update info column */
	pinfo->fragmented = TRUE;
	if (currentSize == totalSize) {
		col_append_str(pinfo->cinfo, COL_INFO, " (Reassembled)");
		g_hash_table_remove(table_totalSize, GUINT_TO_POINTER(requestID));
	} else {
		col_append_fstr(pinfo->cinfo, COL_INFO, " (Fragment %u)", packetNumber + 1);
	}

	offset += dataLength;
}

static void
dissect_0ad_file_transfer_acknowledge(tvbuff_t *tvb)
{
	/* Request ID*/
	proto_tree_add_item(tree_0ad, hf_file_transfer_request_id, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	/* Number Of Packets */
	proto_tree_add_item(tree_0ad, hf_file_transfer_number_of_packets, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
}

#if GAMEVERSION >= 19
static void
dissect_0ad_rejoined(tvbuff_t *tvb)
{
	/* User GUID */
	dissect_0ad_string(tvb, hf_user_guid_length, hf_user_guid, tree_0ad);
}

static void
dissect_0ad_kicked(tvbuff_t *tvb)
{
	/* User GUID */
	dissect_0ad_string(tvb, hf_user_guid_length, hf_user_guid, tree_0ad);

	/* Ban boolean */
	proto_tree_add_item(tree_0ad, hf_ban_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
}
#endif

#if GAMEVERSION >= 20
static void
dissect_0ad_timeout(tvbuff_t *tvb)
{
	/* User GUID */
	dissect_0ad_string(tvb, hf_user_guid_length, hf_user_guid, tree_0ad);

	/* Last received time (unix timestamp) */
	proto_tree_add_item(tree_0ad, hf_last_received_time, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
}

static void
dissect_0ad_performance(tvbuff_t *tvb)
{
	/* User GUID */
	dissect_0ad_string(tvb, hf_user_guid_length, hf_user_guid, tree_0ad);

	/* Mean round trip time */
	proto_tree_add_item(tree_0ad, hf_mean_rtt, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
}
#endif

#if GAMEVERSION >= 21
static void
dissect_0ad_pause(tvbuff_t *tvb)
{
	/* User GUID */
	dissect_0ad_string(tvb, hf_user_guid_length, hf_user_guid, tree_0ad);

	/* Ban boolean */
	proto_tree_add_item(tree_0ad, hf_pause_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
}
#endif

static void
dissect_0ad_loaded_game(tvbuff_t *tvb)
{
	/* Current Turn */
	proto_tree_add_item(tree_0ad, hf_current_turn, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
}

static void
dissect_0ad_end_command_batch(tvbuff_t *tvb)
{
	/* Current Turn */
	proto_tree_add_item(tree_0ad, hf_current_turn, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	/* Turn Length */
	proto_tree_add_item(tree_0ad, hf_turn_length, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
}

static void
dissect_0ad_disconnect(tvbuff_t *tvb, packet_info *pinfo, proto_item *tree_item_0ad)
{
	/* Disconnect Reason */
	const guint32 disconnect_reason = tvb_get_guint32(tvb, offset, ENC_BIG_ENDIAN);
	const gchar *disconnect_reason_text;

	disconnect_reason_text = val_to_str(disconnect_reason, DisconnectReason, "Unknown (0x%02x)");
	proto_tree_add_item(tree_0ad, hf_disconnect_reason, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	/* Update column info*/
	proto_item_append_text(tree_item_0ad, " Disconnect (%s)", disconnect_reason_text);
	col_append_fstr(pinfo->cinfo, COL_INFO, " Disconnect (%s)", disconnect_reason_text);
}


static void
dissect_0ad_sync(tvbuff_t *tvb)
{
	/* Current Turn */
	proto_tree_add_item(tree_0ad, hf_current_turn, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	/* Simulation Hash */
	dissect_0ad_string(tvb, hf_hash_length, hf_hash, tree_0ad);
}

static void
dissect_0ad_simulation_command(tvbuff_t *tvb, proto_item *tree_item_0ad)
{
	dissect_0ad_script_element(tvb, "0ad", "Simulation Command", tree_item_0ad, ENC_BIG_ENDIAN);
}

static void
dissect_0ad_message(tvbuff_t *tvb, packet_info *pinfo, proto_item *tree_item_0ad)
{
	const guint8 messageType = tvb_get_guint8(tvb, offset);
	const gchar *messageTypeName = val_to_str(messageType, NetMessageTypes, "Unknown (0x%02x)");

	/* Update info column */
	/*col_clear(pinfo->cinfo, COL_INFO);*/

	/* TODO: Don't clear the info column. */
	/* Tell ENet not to set the column text, because ENet and 0AD packets are intermingled */
	/* We need a conversation for that probably */
	col_append_fstr(pinfo->cinfo, COL_INFO, ", %s" , messageTypeName);
	proto_item_append_text(tree_item_0ad, " %s", messageTypeName);

	/* Message Type */
	proto_tree_add_item(tree_0ad, hf_message_type, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	/* Serialized Data Length */
	proto_tree_add_item(tree_0ad, hf_serialized_data_length, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	/* Dissect specific message */
	switch(messageType) {
		case 1: dissect_0ad_handshake(tvb, pinfo); break;
		case 2: dissect_0ad_handshake(tvb, pinfo); break;
		case 3: dissect_0ad_server_handshake_response(tvb, pinfo); break;
		case 4: dissect_0ad_authentication(tvb); break;
		case 5: dissect_0ad_authentication_result(tvb); break;
		case 6: dissect_0ad_chat(tvb, pinfo); break;
		case 7: dissect_0ad_ready(tvb, pinfo); break;
#if GAMEVERSION >= 21
		case 8: /* clear all ready */ break;
#endif
		case 8 + COMMAND_OFFSET1: dissect_0ad_gamesetup(tvb, tree_item_0ad); break;
#if GAMEVERSION >= 21
		case 9 + COMMAND_OFFSET1: dissect_0ad_player_assignment_request(tvb, pinfo); break;
#endif
		case 9 + COMMAND_OFFSET2: dissect_0ad_player_assignments(tvb, pinfo); break;
		case 10 + COMMAND_OFFSET2: dissect_0ad_file_transfer_request(tvb); break;
		case 11 + COMMAND_OFFSET2: dissect_0ad_file_transfer_response(tvb); break;
		case 12 + COMMAND_OFFSET2: dissect_0ad_file_transfer_data(tvb, pinfo); break;
		case 13 + COMMAND_OFFSET2: dissect_0ad_file_transfer_acknowledge(tvb); break;
		case 14 + COMMAND_OFFSET2: /* join sync start */ break;
#if GAMEVERSION >= 19
		case 15 + COMMAND_OFFSET2: dissect_0ad_rejoined(tvb); break;
		case 16 + COMMAND_OFFSET2: dissect_0ad_kicked(tvb); break;
#endif
#if GAMEVERSION >= 20
		case 17 + COMMAND_OFFSET2: dissect_0ad_timeout(tvb); break;
		case 18 + COMMAND_OFFSET2: dissect_0ad_performance(tvb); break;
#endif
#if GAMEVERSION >= 21
		case 19 + COMMAND_OFFSET2: dissect_0ad_pause(tvb); break;
#endif
		case 15 + COMMAND_OFFSET3: dissect_0ad_loaded_game(tvb); break;
		case 16 + COMMAND_OFFSET3: /* game start */ break;
		case 17 + COMMAND_OFFSET3: dissect_0ad_end_command_batch(tvb); break;
		case 18 + COMMAND_OFFSET3: dissect_0ad_sync(tvb); break;
		case 19 + COMMAND_OFFSET3: dissect_0ad_sync(tvb); break;
		case 20 + COMMAND_OFFSET3: dissect_0ad_simulation_command(tvb, tree_item_0ad); break;
		default: break;
	}
}

static int
dissect_0ad(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	proto_item *tree_item_0ad = NULL;

	/*conversation_t *conversation = find_conversation(pinfo->fd->num, &pinfo->src,
			&pinfo->dst, PT_UDP, pinfo->srcport, pinfo->dstport, 0);
*/

	/* Reset the offset as one frame can contain multiple 0 A.D. packets,
	* also because we do multiple passes on single packets of 0 A.D. */
	offset = 0;

	/* Update Column Info */
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "0 A.D.");


	/* TODO: Find ENet conversation and disable column info updates, if its data with payload */

	/*
	conversation_add_proto_data(conversation, int proto,
			void *proto_data);
*/

	/* Add protocol subtree on the second run */
	if (tree) {
		tree_item_0ad = proto_tree_add_item(tree, proto_0ad, tvb, 0, -1, ENC_NA);
		tree_0ad = proto_item_add_subtree(tree_item_0ad, ett_0ad_subtree);
	}

	if (tvb_captured_length_remaining(tvb, offset) == 4)
		dissect_0ad_disconnect(tvb, pinfo, tree_0ad);
	else
		dissect_0ad_message(tvb, pinfo, tree_0ad);

	return offset;
}

static gboolean
dissect_0ad_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	if (pinfo->srcport != PS_DEFAULT_PORT && pinfo->destport != PS_DEFAULT_PORT)
		return FALSE;

	dissect_0ad(tvb, pinfo, tree, data);
	return TRUE;
}

static void
setup_dissector(void)
{
	reassembly_table_init(&msg_fragment_table, &addresses_reassembly_table_functions);
	table_guid_username = g_hash_table_new(g_str_hash, g_str_equal);
	table_packetNr = g_hash_table_new(g_direct_hash, g_direct_equal);
	table_fileSize = g_hash_table_new(g_direct_hash, g_direct_equal);
	table_totalSize = g_hash_table_new(g_direct_hash, g_direct_equal);
}

static void
cleanup_dissector(void)
{
	reassembly_table_destroy(&msg_fragment_table);
	g_hash_table_destroy(table_guid_username);
	g_hash_table_destroy(table_packetNr);
	g_hash_table_destroy(table_totalSize);
	g_hash_table_destroy(table_fileSize);
	table_guid_username = NULL;
	table_packetNr = NULL;
	table_totalSize = NULL;
	table_fileSize = NULL;
}

void
proto_register_0ad(void)
{
	/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_0ad_subtree,
		&ett_0ad_script_array_subtree,
		&ett_0ad_player_assignment_subtree,
		&ett_msg_fragment_subtree,
		&ett_msg_fragments_subtree
	};

	proto_0ad = proto_register_protocol (
		"0 A.D. Protocol",
		"0 A.D.",
		"0ad"
	);

	proto_register_field_array(proto_0ad, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	register_init_routine( setup_dissector );
	register_cleanup_routine( cleanup_dissector );
}

void
proto_reg_handoff_0ad(void)
{
	/* Tell wireshark to treat all traffic on that port as ENet */
	dissector_handle_t handle_enet = find_dissector("enet");
	dissector_add_uint("udp.port", PS_DEFAULT_PORT, handle_enet);

	/* Dissect ENet traffic on that UDP port by using heuristic registration */
	handle_0ad = create_dissector_handle(dissect_0ad, proto_0ad);
	heur_dissector_add("enet", dissect_0ad_heur, "0 A.D.", "0ad", proto_0ad, HEURISTIC_ENABLE);
}
