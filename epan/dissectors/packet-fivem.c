#include "config.h"

#include <epan/conversation.h>
#include <epan/packet.h>
#include <epan/reassemble.h>
#include <epan/exceptions.h>
#ifdef HAVE_LZ4
#include <lz4.h>
#endif

#define FIVEM_PORT 30120

static int proto_fivem = -1;
static gint ett_fivem = -1;

static dissector_handle_t handle_data;
static dissector_handle_t msgpack_handle;

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

static int hf_message_type = -1;
static int hf_connect_string = -1;
static int hf_frame_index = -1;
static int hf_packedclones_frame_index = -1;
static int hf_packedclones_data = -1;
static int hf_objects_count = -1;
static int hf_object_skip = -1;
static int hf_object_take = -1;
static int hf_object_id = -1;
static int hf_netevent_netid = -1;
static int hf_netevent_name_size = -1;
static int hf_netevent_name = -1;
static int hf_netevent_payload = -1;
static int hf_serverevent_name_size = -1;
static int hf_serverevent_name = -1;
static int hf_serverevent_payload = -1;

static hf_register_info hf[] = {
    { &hf_message_type,
            { "Message Type", "fivem.message_type",
            FT_UINT32, BASE_HEX,
            VALS(messagetypes), 0x0,
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
            FT_NONE, BASE_NONE,
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
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
    },
};

static gint *ett[] = {
    &ett_fivem
};

static void
dissect_fivem_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *fivem_tree, const guint32 messageType, gint *offset) {
    proto_item *item = NULL;
    proto_tree *fivem_tree_payload = NULL;

    switch (messageType) {
    default:
        break;
    case 0x00000000:
        break;
    case 0x01000000:
        item = proto_tree_add_item(fivem_tree, hf_connect_string, tvb, *offset, -1, ENC_ASCII);
        *offset += 4;
        break;
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
    case 0x3ffaff53: // msgFrame
        item = proto_tree_add_item(fivem_tree, hf_frame_index, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
        *offset += 4;
        break;
    case 0x35c8e181: // msgPackedClones
    {
        item = proto_tree_add_item(fivem_tree, hf_packedclones_frame_index, tvb, *offset, 8, ENC_LITTLE_ENDIAN);
        *offset += 8;

#ifdef HAVE_LZ4
        tvbuff_t *tvb_decompressed = NULL;
        guint orig_size = 16384;
        guchar *decompressed_buffer = decompressed_buffer = (guchar *)wmem_alloc(pinfo->pool, orig_size);

        gint ret = LZ4_decompress_safe(
            tvb_get_ptr(tvb, *offset, -1),
            decompressed_buffer,
            tvb_captured_length_remaining(tvb, *offset),
            orig_size);

        tvb_decompressed = tvb_new_child_real_data(tvb, decompressed_buffer, ret, ret);
        add_new_data_source(pinfo, tvb_decompressed, "Decompressed Data");

        item = proto_tree_add_item(fivem_tree, hf_packedclones_data, tvb, *offset, -1, ENC_NA);
        *offset += tvb_captured_length_remaining(tvb, *offset);
#endif
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
    case 0x639e56ca: // msgEnd
        break;
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
        fivem_tree_payload = proto_item_add_subtree(fivem_tree, ett_fivem);

        while (tvb_captured_length_remaining(tvb, *offset) > 0) {
            tvbuff_t *tvb_payload = tvb_new_subset_remaining(tvb, *offset);

            call_dissector(msgpack_handle, tvb_payload, pinfo, fivem_tree_payload);
            *offset += tvb_captured_length(tvb_payload);
        }
        break;
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

    dissect_fivem_message(tvb, pinfo, fivem_tree, messageType, &offset);

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
}

void
proto_reg_handoff_fivem(void)
{
    static dissector_handle_t fivem_handle;
    dissector_handle_t enet_handle = find_dissector("enet");

    fivem_handle = create_dissector_handle(dissect_fivem, proto_fivem);
    dissector_add_uint("udp.port", FIVEM_PORT, enet_handle);
    dissector_add_for_decode_as("udp.port", fivem_handle);

    heur_dissector_add("enet", dissect_fivem_heur, "FiveM", "fivem", proto_fivem, HEURISTIC_ENABLE);

    handle_data = find_dissector("data");
    msgpack_handle = find_dissector("msgpack");
}
