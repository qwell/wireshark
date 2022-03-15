#include "config.h"

#include <epan/conversation.h>
#include <epan/packet.h>
#include <epan/reassemble.h>
#include <epan/exceptions.h>
#include <math.h>
#ifdef HAVE_LZ4
#include <lz4.h>
#endif

#define FIVEM_PORT 30120

static int proto_fivem = -1;
static gint ett_fivem = -1;

static gint ett_fivem_fragment = -1;
static gint ett_fivem_fragments = -1;

static dissector_handle_t handle_data;
static dissector_handle_t msgpack_handle;

static reassembly_table msg_reassembly_table;

static const value_string messagetypes[] = {
    { 0xe0b50981, "ARCHETYPE_FILE" },
    { 0xbe28cc09, "CMloInstanceDef" },
    { 0xd3cda630, "CustomMatrixDef" },
    { 0xd220badc, "HandBrakeSwingSettings" },
    { 0x7f3e6bc1, "fAntiRollBarBiasFront" },
    { 0xa21a97e2, "fDriveBiasFront" },
    { 0xddaa4a86, "fInitialDragCoeff" },
    { 0x7f8f1497, "fInitialDriveMaxFlatVel" },
    { 0x990c9cfb, "fPercentSubmerged" },
    { 0xabd5eaea, "fSuspensionBiasFront" },
    { 0xa55bb5ef, "fSuspensionCompDamp" },
    { 0x2b1a96ef, "fTractionCurveLateral" },
    { 0x89bfa5b9, "fTractionCurveMax" },
    { 0x68dd2160, "fTractionSpringDeltaMax" },
    { 0xbce2d4a5, "gameStateAck" },
    { 0x6e6af8d2, "gameStateNAck" },
    { 0x83e77609, "msgArrayUpdate" },
    { 0x83d5cb6a, "msgConVars" },
    { 0x639e56ca, "msgEnd" },
    { 0x2a6a210f, "msgEntityCreate" },
    { 0x3ffaff53, "msgFrame" },
    { 0xde30eab3, "msgIHost" },
    { 0x7afd3773, "msgNetEvent" },
    { 0xa8660d10, "msgNetGameEvent" },
    { 0x8195e348, "msgObjectIds" },
    { 0xb4fd8d25, "msgPackedAcks" },
    { 0x35c8e181, "msgPackedClones" },
    { 0x5b063b07, "msgPaymentRequest" },
    { 0x5d54172e, "msgReassembledEvent" },
    { 0xcf11e6b8, "msgRequestObjectIds" },
    { 0x4acde4af, "msgResStart" },
    { 0xd755e845, "msgResStop" },
    { 0x5b4438e9, "msgRoute" },
    { 0xc9f1b00a, "msgRpcEntityCreation" },
    { 0x17ab1c21, "msgRpcNative" },
    { 0xc44f8db1, "msgServerCommand" },
    { 0x186e77fa, "msgServerEvent" },
    { 0x591a3dde, "msgStateBag" },
    { 0xed376ee5, "msgTimeSync" },
    { 0xf803131c, "msgTimeSyncReq" },
    { 0xb63848e0, "msgWorldGrid" },
    { 0x61152c85, "msgWorldGrid3" },
    { 0x68cf788b, "nInitialDriveGears" },
    { 0x958ee5d6, "strDamageFlags" },
    { 0xf61f704c, "strHandlingFlags" },
    { 0x56343ab5, "strModelFlags" },

    { 0x6f6e7365, ""},
    { 0x01000000, "CONNECTED"}, // This isn't a RageString - we made up the text.
    { 0x00000000, NULL },
};

static int hf_fivem_fragments = -1;
static int hf_fivem_fragment = -1;
static int hf_fivem_fragment_overlap = -1;
static int hf_fivem_fragment_overlap_conflicts = -1;
static int hf_fivem_fragment_multiple_tails = -1;
static int hf_fivem_fragment_too_long_fragment = -1;
static int hf_fivem_fragment_error = -1;
static int hf_fivem_fragment_count = -1;
static int hf_fivem_reassembled_in = -1;
static int hf_fivem_reassembled_length = -1;
static int hf_fivem_reassembled_data = -1;

static int hf_message_type = -1;
static int hf_raw_payload = -1;
static int hf_connect_string = -1;
static int hf_frame_index = -1;
static int hf_packedclones_frame_index = -1;
static int hf_packedclones_data = -1;
static int hf_objects_count = -1;
static int hf_object_skip = -1;
static int hf_object_take = -1;
static int hf_object_id = -1;
static int hf_route_netid = -1;
static int hf_route_size = -1;
static int hf_statebag_name_size = -1;
static int hf_statebag_name = -1;
static int hf_netevent_netid = -1;
static int hf_netevent_name_size = -1;
static int hf_netevent_name = -1;
static int hf_netevent_payload = -1;
static int hf_serverevent_name_size = -1;
static int hf_serverevent_name = -1;
static int hf_serverevent_payload = -1;
static int hf_reassembledevent_eventlow = -1;
static int hf_reassembledevent_eventhigh = -1;
static int hf_reassembledevent_packet_index = -1;
static int hf_reassembledevent_total_packets = -1;
static int hf_reassembledevent_packet_size = -1;
static int hf_reassembledevent_payload = -1;
static int hf_reassembledevent_reassembled_name = -1;
static int hf_reassembledevent_reassembled_name_size = -1;

static hf_register_info hf[] = {
    { &hf_fivem_fragments,
            { "Message fragments", "fivem.fragments",
            FT_BYTES, BASE_NONE,
            NULL, 0x00,
            NULL, HFILL }
    },
    { &hf_fivem_fragment,
            { "Message fragment", "fivem.fragment",
            FT_FRAMENUM, BASE_NONE,
            NULL, 0x00,
            NULL, HFILL }
    },
    { &hf_fivem_fragment_overlap,
            { "Message fragment overlap", "fivem.fragment.overlap",
            FT_BOOLEAN, 0,
            NULL, 0x00,
            NULL, HFILL }
    },
    { &hf_fivem_fragment_overlap_conflicts,
            { "Message fragment overlapping with conflicting data", "fivem.fragment.overlap.conflicts",
            FT_BOOLEAN, 0,
            NULL, 0x00,
            NULL, HFILL }
    },
    { &hf_fivem_fragment_multiple_tails,
            { "Message has multiple tail fragments", "fivem.fragment.multiple_tails",
            FT_BOOLEAN, 0,
            NULL, 0x00,
            NULL, HFILL }
    },
    { &hf_fivem_fragment_too_long_fragment,
            { "Message fragment too long", "fivem.fragment.too_long_fragment",
            FT_BOOLEAN, 0,
            NULL, 0x00,
            NULL, HFILL }
    },
    { &hf_fivem_fragment_error,
            { "Message defragmentation error", "fivem.fragment.error",
            FT_FRAMENUM, BASE_NONE,
            NULL, 0x00,
            NULL, HFILL }
    },
    { &hf_fivem_fragment_count,
            { "Message fragment count", "fivem.fragment.count",
            FT_UINT32, BASE_DEC,
            NULL, 0x00,
            NULL, HFILL }
    },
    { &hf_fivem_reassembled_in,
            { "Reassembled in", "fivem.reassembled.in",
            FT_FRAMENUM, BASE_NONE,
            NULL, 0x00,
            NULL, HFILL }
    },
    { &hf_fivem_reassembled_length,
            { "Reassembled length", "fivem.reassembled.length",
            FT_UINT32, BASE_DEC,
            NULL, 0x00,
            NULL, HFILL }
    },
    { &hf_fivem_reassembled_data,
            { "Reassembled data", "fivem.reassembled.data",
            FT_BYTES, BASE_NONE,
            NULL, 0x00,
            NULL, HFILL }
    },
    { &hf_message_type,
            { "Message Type", "fivem.message_type",
            FT_UINT32, BASE_HEX,
            VALS(messagetypes), 0x0,
            NULL, HFILL }
    },
    { &hf_raw_payload,
            { "Raw Payload", "fivem.raw_payload",
            FT_BYTES, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
    },
    { &hf_connect_string,
            { "Connect String", "fivem.connect_string",
            FT_STRING, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
    },
    { &hf_frame_index,
            { "Frame index", "fivem.frame.index",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
    },
    { &hf_packedclones_frame_index,
            { "PackedClones FrameIndex", "fivem.packedclones.frame_index",
            FT_UINT64, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
    },
    { &hf_packedclones_data,
            { "PackedClones Data", "fivem.packedclones.frame_index",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
    },
    { &hf_objects_count,
            { "Objects count", "fivem.objects.count",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
    },
    { &hf_object_skip,
            { "Object Skip", "fivem.object.skip",
            FT_UINT16, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
    },
    { &hf_object_take,
            { "Object Take", "fivem.object.take",
            FT_UINT16, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
    },
    { &hf_object_id,
            { "Object Id", "fivem.object.id",
            FT_UINT16, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
    },
    { &hf_route_netid,
            { "Route NetID", "fivem.route.netid",
            FT_UINT16, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
    },
    { &hf_route_size,
            { "Route Size", "fivem.route.size",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
    },
    { &hf_statebag_name_size,
            { "StateBag Name Size", "fivem.statebag.name_size",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
    },
    { &hf_statebag_name,
            { "StateBag Name", "fivem.statebag.name",
            FT_STRING, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
    },
    { &hf_netevent_netid,
            { "NetEvent NetID", "fivem.netevent.netid",
            FT_UINT16, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
    },
    { &hf_netevent_name_size,
            { "NetEvent Name Size", "fivem.netevent.name_size",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
    },
    { &hf_netevent_name,
            { "NetEvent Name", "fivem.netevent.name",
            FT_STRING, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
    },
    { &hf_netevent_payload,
            { "NetEvent Payload", "fivem.netevent.payload",
            FT_BYTES, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
    },
    { &hf_serverevent_name_size,
            { "ServerEvent Name Size", "fivem.serverevent.name_size",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
    },
    { &hf_serverevent_name,
            { "ServerEvent Name", "fivem.serverevent.name",
            FT_STRING, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
    },
    { &hf_serverevent_payload,
            { "ServerEvent Payload", "fivem.serverevent.payload",
            FT_BYTES, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
    },
    { &hf_reassembledevent_eventlow,
            { "ReassembledEvent Event Low", "fivem.reassembledevent.eventlow",
            FT_UINT32, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
    },
    { &hf_reassembledevent_eventhigh,
            { "ReassembledEvent Event High", "fivem.reassembledevent.eventhigh",
            FT_UINT32, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
    },
    { &hf_reassembledevent_packet_index,
            { "ReassembledEvent Packet Index", "fivem.reassembledevent.packet_index",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
    },
    { &hf_reassembledevent_total_packets,
            { "ReassembledEvent Total Packets", "fivem.reassembledevent.total_packets",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
    },
    { &hf_reassembledevent_packet_size,
            { "ReassembledEvent Packet Size", "fivem.reassembledevent.packet_size",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
    },
    { &hf_reassembledevent_payload,
            { "ReassembledEvent Payload", "fivem.reassembledevent.payload",
            FT_BYTES, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
    },
    { &hf_reassembledevent_reassembled_name,
            { "ReassembledEvent Name", "fivem.reassembledevent.name",
            FT_STRING, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
    },
    { &hf_reassembledevent_reassembled_name_size,
            { "ReassembledEvent Name Size", "fivem.reassembledevent.name_size",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
    },
};

static const fragment_items fivem_frag_items = {
    /* Fragment subtrees */
    &ett_fivem_fragment,
    &ett_fivem_fragments,
    /* Fragment fields */
    &hf_fivem_fragments,
    &hf_fivem_fragment,
    &hf_fivem_fragment_overlap,
    &hf_fivem_fragment_overlap_conflicts,
    &hf_fivem_fragment_multiple_tails,
    &hf_fivem_fragment_too_long_fragment,
    &hf_fivem_fragment_error,
    &hf_fivem_fragment_count,
    /* Reassembled in field */
    &hf_fivem_reassembled_in,
    /* Reassembled length field */
    &hf_fivem_reassembled_length,
    /* Reassembled data field */
    &hf_fivem_reassembled_data,
    /* Tag */
    "Message fragments"
};

static gint *ett[] = {
    &ett_fivem,
    &ett_fivem_fragment,
    &ett_fivem_fragments,
};

typedef struct enet_command_header {
    guint8 command;
    guint8 channel;
    guint16 sequence;
} enet_command_header;

static void
dissect_fivem_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *fivem_tree, const guint32 messageType, gint *offset, void *data) {
    enet_command_header *header = data;

    proto_item *item = NULL;
    proto_tree *fivem_tree_payload = NULL;

    switch (messageType) {
    default:
        break;
    case 0x00000000:
        break;
    case 0x01000000:
    {
        item = proto_tree_add_item(fivem_tree, hf_connect_string, tvb, *offset, -1, ENC_ASCII);
        *offset += tvb_captured_length(tvb);
        break;
    }
    case 0x186e77fa: // msgServerEvent
    {
        uint16_t name_size = tvb_get_guint16(tvb, *offset, ENC_LITTLE_ENDIAN);
        item = proto_tree_add_item(fivem_tree, hf_serverevent_name_size, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
        *offset += 2;

        item = proto_tree_add_item(fivem_tree, hf_serverevent_name, tvb, *offset, name_size, ENC_ASCII);
        *offset += name_size;

        fivem_tree_payload = proto_item_add_subtree(fivem_tree, ett_fivem);

        while (tvb_captured_length_remaining(tvb, *offset) > 0) {
            tvbuff_t *tvb_payload = tvb_new_subset_remaining(tvb, *offset);

            call_dissector(msgpack_handle, tvb_payload, pinfo, fivem_tree_payload);
            *offset += tvb_captured_length(tvb_payload);
        }

        break;
    }
    case 0x35c8e181: // msgPackedClones
    {
        item = proto_tree_add_item(fivem_tree, hf_packedclones_frame_index, tvb, *offset, 8, ENC_LITTLE_ENDIAN);
        *offset += 8;

#ifdef HAVE_LZ4
        guint orig_size = 16384;
        guint8 *decompressed_buffer = (guint8 *)wmem_alloc(pinfo->pool, orig_size);
        tvbuff_t *tvb_decompressed;

        gint ret = LZ4_decompress_safe(
            tvb_get_ptr(tvb, *offset, -1),
            decompressed_buffer,
            tvb_captured_length_remaining(tvb, *offset),
            orig_size);

        tvb_decompressed = tvb_new_child_real_data(tvb, decompressed_buffer, ret, ret);
        add_new_data_source(pinfo, tvb_decompressed, "Decompressed Data");
#endif

        while (tvb_captured_length_remaining(tvb, *offset) > 0) {
            tvbuff_t *tvb_payload = tvb_new_subset_remaining(tvb, *offset);

            item = proto_tree_add_item(fivem_tree, hf_packedclones_data, tvb_payload, 0, -1, ENC_NA);
            *offset += tvb_captured_length(tvb_payload);
        }

        break;
    }
    case 0x3ffaff53: // msgFrame
    {
        item = proto_tree_add_item(fivem_tree, hf_frame_index, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
        *offset += 4;
        break;
    }
    case 0x591a3dde: // msgStateBag
    {
        int i = 0;
        while (i < 2 && tvb_captured_length_remaining(tvb, *offset) > 0) {
            i++;
            *offset += 1;

            guint8 name_size = tvb_get_guint8(tvb, *offset);
            item = proto_tree_add_item(fivem_tree, hf_statebag_name_size, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
            *offset += 1;

            item = proto_tree_add_item(fivem_tree, hf_statebag_name, tvb, *offset, name_size, ENC_ASCII);
            *offset += name_size;
        }

        fivem_tree_payload = proto_item_add_subtree(fivem_tree, ett_fivem);

        while (tvb_captured_length_remaining(tvb, *offset) > 0) {
            tvbuff_t *tvb_payload = tvb_new_subset_remaining(tvb, *offset);

            call_dissector(msgpack_handle, tvb_payload, pinfo, fivem_tree_payload);
            *offset += tvb_captured_length(tvb_payload);
        }
        break;
    }
    case 0x5b4438e9: // msgRoute
    {
        item = proto_tree_add_item(fivem_tree, hf_route_netid, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
        *offset += 2;

        item = proto_tree_add_item(fivem_tree, hf_route_size, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
        *offset += 2;

        break;
    }
    case 0x5d54172e: // msgReassembledEvent
    {
        fragment_head *frag_msg;
        tvbuff_t *tvb_reassembled = NULL;

        guint32 eventlow = tvb_get_guint32(tvb, *offset, ENC_LITTLE_ENDIAN);
        item = proto_tree_add_uint(fivem_tree, hf_reassembledevent_eventlow, tvb, *offset, 4, eventlow);
        *offset += 4;

        item = proto_tree_add_item(fivem_tree, hf_reassembledevent_eventhigh, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
        *offset += 4;

        guint32 bitoffset = *offset * 8;

        guint32 packetIdx = tvb_get_bits32(tvb, bitoffset, 17, ENC_NA);
        item = proto_tree_add_bits_item(fivem_tree, hf_reassembledevent_packet_index, tvb, bitoffset, 17, ENC_NA);
        bitoffset += 17;

        guint32 totalPackets = tvb_get_bits32(tvb, bitoffset, 17, ENC_NA);
        item = proto_tree_add_bits_item(fivem_tree, hf_reassembledevent_total_packets, tvb, bitoffset, 17, ENC_NA);
        bitoffset += 17;

        guint16 thisBytes = tvb_get_bits16(tvb, bitoffset, 10, ENC_NA);
        item = proto_tree_add_bits_item(fivem_tree, hf_reassembledevent_packet_size, tvb, bitoffset, 10, ENC_NA);
        bitoffset += 10;

        tvbuff_t *tvb_bits = NULL;
        if (thisBytes > 0) {
            tvb_bits = tvb_new_octet_aligned(tvb, bitoffset, thisBytes * 8);

            guint foo = eventlow | header->sequence;
            guint bar = foo;
            foo = bar;
        }
        else {
            tvb_bits = tvb_new_subset_length(tvb, 0, 0);
        }

        // Eat the rest of tvb, so we know which bytes in the output display are used - even if they don't properly align.
        *offset = 0;
        item = proto_tree_add_bytes(fivem_tree, hf_reassembledevent_payload, tvb, bitoffset >> 3, -1, tvb_get_ptr(tvb_bits, *offset, -1));

        bool save_fragmented = pinfo->fragmented;
        frag_msg = fragment_add_seq_check(
            &msg_reassembly_table,
            tvb_bits, *offset, pinfo,
            eventlow /*| header->sequence*/, /* Yeah, I don't know.  Event low and/or event high weren't unique enough, so let's add something to it. */
            NULL, packetIdx,
            tvb_captured_length_remaining(tvb_bits, *offset),
            !(packetIdx == totalPackets - 1));

        tvb_reassembled = process_reassembled_data(
            tvb_bits, *offset, pinfo,
            "Reassembled Message", frag_msg, &fivem_frag_items,
            NULL, fivem_tree);

        /* Update info column */
        pinfo->fragmented = TRUE;
        if (tvb_reassembled) {
            int reassembledoffset = 0;
            col_append_fstr(pinfo->cinfo, COL_INFO, " (%u of %u, Reassembled)", packetIdx + 1, totalPackets);

            if (tvb_captured_length_remaining(tvb_reassembled, reassembledoffset) > 0) {
                fivem_tree_payload = proto_item_add_subtree(fivem_tree, ett_fivem);

                *offset += 1;

                guint8 name_size = tvb_get_guint8(tvb_reassembled, reassembledoffset);
                proto_tree_add_uint(fivem_tree_payload, hf_reassembledevent_reassembled_name_size, tvb_reassembled, reassembledoffset, 1, name_size);
                reassembledoffset += 1;

                proto_tree_add_item(fivem_tree_payload, hf_reassembledevent_reassembled_name, tvb_reassembled, reassembledoffset, name_size, ENC_ASCII);
                reassembledoffset += name_size;

                while (tvb_captured_length_remaining(tvb_reassembled, reassembledoffset) > 0) {
                    tvbuff_t *tvb_payload = tvb_new_subset_remaining(tvb_reassembled, reassembledoffset);

                    reassembledoffset += call_dissector(msgpack_handle, tvb_payload, pinfo, fivem_tree_payload);
                }
            }
        }
        else {
            col_append_fstr(pinfo->cinfo, COL_INFO, " (%u of %u)", packetIdx + 1, totalPackets);
        }

        pinfo->fragmented = save_fragmented;

        *offset = (int)ceil((double)bitoffset / 8) + thisBytes;
        *offset = tvb_captured_length(tvb);

        break;
    }
    case 0x639e56ca: // msgEnd
    {
        break;
    }
    case 0x7afd3773: // msgNetEvent
    {
        item = proto_tree_add_item(fivem_tree, hf_netevent_netid, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
        *offset += 2;

        uint16_t name_size = tvb_get_guint16(tvb, *offset, ENC_LITTLE_ENDIAN);
        item = proto_tree_add_item(fivem_tree, hf_netevent_name_size, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
        *offset += 2;

        item = proto_tree_add_item(fivem_tree, hf_netevent_name, tvb, *offset, name_size, ENC_ASCII);
        *offset += name_size;

        fivem_tree_payload = proto_item_add_subtree(fivem_tree, ett_fivem);

        while (tvb_captured_length_remaining(tvb, *offset) > 0) {
            tvbuff_t *tvb_payload = tvb_new_subset_remaining(tvb, *offset);

            call_dissector(msgpack_handle, tvb_payload, pinfo, fivem_tree_payload);
            *offset += tvb_captured_length(tvb_payload);
        }
        break;
    }
    case 0x8195e348: // msgObjectIds
    {
        guint16 count = tvb_get_guint16(tvb, *offset, ENC_LITTLE_ENDIAN);
        item = proto_tree_add_item(fivem_tree, hf_objects_count, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
        *offset += 2;

        int last = 0;
        for (uint16_t i = 0; i < count; i++) {
            proto_tree *fivem_tree_object = proto_item_add_subtree(fivem_tree, ett_fivem);

            guint16 skip = tvb_get_guint16(tvb, *offset, ENC_LITTLE_ENDIAN);
            item = proto_tree_add_item(fivem_tree_object, hf_object_skip, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
            *offset += 2;

            guint16 take = tvb_get_guint16(tvb, *offset, ENC_LITTLE_ENDIAN);
            item = proto_tree_add_item(fivem_tree_object, hf_object_take, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
            *offset += 2;

            last += skip + 1;
            for (int j = 0; j <= take; j++) {
                item = proto_tree_add_uint(fivem_tree_object, hf_object_id, tvb, 0, 0, last++);
                proto_item_set_generated(item);
            }
        }
        break;
    }
    case 0x83d5cb6a: // msgConVars
    {
        fivem_tree_payload = proto_item_add_subtree(fivem_tree, ett_fivem);

        while (tvb_captured_length_remaining(tvb, *offset) > 0) {
            tvbuff_t *tvb_payload = tvb_new_subset_remaining(tvb, *offset);

            call_dissector(msgpack_handle, tvb_payload, pinfo, fivem_tree_payload);
            *offset += tvb_captured_length(tvb_payload);
        }
        break;
    }
    }

    if (tvb_captured_length_remaining(tvb, *offset)) {
        item = proto_tree_add_item(fivem_tree, hf_raw_payload, tvb, *offset, -1, ENC_NA);
        *offset += tvb_captured_length_remaining(tvb, *offset);
    }

    return;
}

static int
dissect_fivem(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
    gint offset = 0;
    proto_tree *fivem_tree = NULL;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "FiveM");

    proto_item *ti = proto_tree_add_item(tree, proto_fivem, tvb, offset, -1, ENC_NA);
    fivem_tree = proto_item_add_subtree(ti, ett_fivem);

    const guint32 messageType = tvb_get_guint32(tvb, offset, ENC_NA);
    const gchar *messageTypeName = val_to_str(messageType, messagetypes, "0x%08x");

    col_append_fstr(pinfo->cinfo, COL_INFO, " (%s)", messageTypeName);
    proto_item_append_text(fivem_tree, ", %s", messageTypeName);

    proto_tree_add_item(fivem_tree, hf_message_type, tvb, offset, 4, ENC_NA);
    offset += 4;

    dissect_fivem_message(tvb, pinfo, fivem_tree, messageType, &offset, data);

    return offset;// tvb_captured_length(tvb);
}

static gboolean
dissect_fivem_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    if (pinfo->srcport != FIVEM_PORT && pinfo->destport != FIVEM_PORT) {
        return FALSE;
    }

    dissect_fivem(tvb, pinfo, tree, data);
    return TRUE;
}

static void
setup_dissector(void)
{
    reassembly_table_init(&msg_reassembly_table, &addresses_reassembly_table_functions);
}

static void
cleanup_dissector(void)
{
    reassembly_table_destroy(&msg_reassembly_table);
}

void
proto_register_fivem(void)
{
    proto_fivem = proto_register_protocol(
        "FiveM Protocol",
        "FiveM",
        "fivem"
    );

    proto_register_field_array(proto_fivem, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    register_init_routine(setup_dissector);
    register_cleanup_routine(cleanup_dissector);
}

void
proto_reg_handoff_fivem(void)
{
    static dissector_handle_t fivem_handle;
    dissector_handle_t enet_handle = find_dissector("enet");

    fivem_handle = create_dissector_handle(dissect_fivem, proto_fivem);
    dissector_add_uint("udp.port", FIVEM_PORT, enet_handle);
    dissector_add_for_decode_as("udp.port", fivem_handle);
    dissector_add_uint("tcp.port", FIVEM_PORT, enet_handle);
    dissector_add_for_decode_as("tcp.port", fivem_handle);

    heur_dissector_add("enet", dissect_fivem_heur, "FiveM", "fivem", proto_fivem, HEURISTIC_ENABLE);

    handle_data = find_dissector("data");
    msgpack_handle = find_dissector("msgpack");
}
