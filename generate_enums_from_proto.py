#!/usr/bin/env python

import re
from keyword import kwlist
from google.protobuf.internal.enum_type_wrapper import EnumTypeWrapper
from steam.enums import common as common_enums

kwlist = set(kwlist + ['None'])

_proto_modules = [
    'clientmetrics_pb2',
    'content_manifest_pb2',
    'contenthubs_pb2',
    'encrypted_app_ticket_pb2',
    'enums_pb2',
    'enums_clientserver_pb2',
    'enums_productinfo_pb2',
    'htmlmessages_pb2',
    'offline_ticket_pb2',

    'steamdatagram_messages_auth_pb2',
    'steamdatagram_messages_sdr_pb2',

    'steammessages_accounthardware_pb2',
    'steammessages_appoverview_pb2',
    'steammessages_auth_pb2',
    'steammessages_base_pb2',
    'steammessages_broadcast_pb2',
    'steammessages_chat_pb2',
    'steammessages_childprocessquery_pb2',
    'steammessages_client_objects_pb2',
    'steammessages_clientlanp2p_pb2',
    'steammessages_clientmetrics_pb2',
    'steammessages_clientnotificationtypes_pb2',
    'steammessages_clientserver_pb2',
    'steammessages_clientserver_2_pb2',
    'steammessages_clientserver_appinfo_pb2',
    'steammessages_clientserver_friends_pb2',
    'steammessages_clientserver_gameservers_pb2',
    'steammessages_clientserver_lbs_pb2',
    'steammessages_clientserver_login_pb2',
    'steammessages_clientserver_mms_pb2',
    'steammessages_clientserver_ucm_pb2',
    'steammessages_clientserver_uds_pb2',
    'steammessages_clientserver_userstats_pb2',
    'steammessages_clientserver_video_pb2',
    'steammessages_clientsettings_pb2',
    'steammessages_cloud_pb2',
    'steammessages_community_pb2',
    'steammessages_contentsystem_pb2',
    'steammessages_credentials_pb2',
    'steammessages_datapublisher_pb2',
    'steammessages_depotbuilder_pb2',
    'steammessages_econ_pb2',
    'steammessages_familygroups_pb2',
    'steammessages_friendmessages_pb2',
    'steammessages_gamenetworking_pb2',
    'steammessages_gamenetworkingui_pb2',
    'steammessages_gamenotifications_pb2',
    'steammessages_gamerecording_pb2',
    'steammessages_gamerecording_objects_pb2',
    'steammessages_gameservers_pb2',
    'steammessages_hiddevices_pb2',
    'steammessages_inventory_pb2',
    'steammessages_linkfilter_pb2',
    'steammessages_lobbymatchmaking_pb2',
    'steammessages_market_pb2',
    'steammessages_marketingmessages_pb2',
    'steammessages_notifications_pb2',
    'steammessages_offline_pb2',
    'steammessages_parental_pb2',
    'steammessages_parental_objects_pb2',
    'steammessages_parties_pb2',
    'steammessages_partnerapps_pb2',
    'steammessages_player_pb2',
    'steammessages_publishedfile_pb2',
    'steammessages_qms_pb2',
    'steammessages_remoteclient_pb2',
    'steammessages_remoteclient_discovery_pb2',
    'steammessages_remoteclient_service_pb2',
    'steammessages_remoteclient_service_messages_pb2',
    'steammessages_remoteplay_pb2',
    'steammessages_secrets_pb2',
    'steammessages_shader_pb2',
    'steammessages_site_license_pb2',
    'steammessages_sitelicenseclient_pb2',
    'steammessages_siteserverui_pb2',
    'steammessages_steamtv_pb2',
    'steammessages_store_pb2',
    'steammessages_storebrowse_pb2',
    'steammessages_timedtrial_pb2',
    'steammessages_twofactor_pb2',
    'steammessages_unified_base_pb2',
    'steammessages_unified_test_pb2',
    'steammessages_useraccount_pb2',
    'steammessages_vac_pb2',
    'steammessages_video_pb2',
    'steammessages_virtualcontroller_pb2',
    'steammessages_workshop_pb2',

    'steamnetworkingsockets_messages_pb2',
    'steamnetworkingsockets_messages_certs_pb2',
    'steamnetworkingsockets_messages_udp_pb2',

    'webuimessages_achievements_pb2',
    'webuimessages_base_pb2',
    'webuimessages_bluetooth_pb2',
    'webuimessages_gamenotes_pb2',
    'webuimessages_gamerecording_pb2',
    'webuimessages_gamerecordingfiles_pb2',
    'webuimessages_gamescope_pb2',
    'webuimessages_hardwareupdate_pb2',
    'webuimessages_leds_pb2',
    'webuimessages_sharedjscontext_pb2',
    'webuimessages_sleep_pb2',
    'webuimessages_steamengine_pb2',
    'webuimessages_steaminput_pb2',
    'webuimessages_steamos_pb2',
    'webuimessages_storagedevicemanager_pb2',
    'webuimessages_systemmanager_pb2',
    'webuimessages_transport_pb2',
    'webuimessages_transportvalidation_pb2',
]

_proto_module = __import__("steam.protobufs", globals(), locals(), _proto_modules, 0)

classes = {}

for name in _proto_modules:

    proto = getattr(_proto_module, name)
    gvars = globals()

    for class_name, value in proto.__dict__.items():
        if not isinstance(value, EnumTypeWrapper) or hasattr(common_enums, class_name):
            continue

        attrs_starting_with_number = False
        attrs = {}

        for ikey, ivalue in value.items():
            ikey = re.sub(r'^(k_)?(%s_)?' % class_name, '', ikey)
            attrs[ikey] = ivalue

            if ikey[0:1].isdigit() or ikey in kwlist:
                attrs_starting_with_number = True

        classes[class_name] = attrs, attrs_starting_with_number

# print out enums as python Enum
print("from steam.enums.base import SteamIntEnum")

for class_name, (attrs, attrs_starting_with_number) in sorted(classes.items(), key=lambda x: x[0].lower()):
        if attrs_starting_with_number:
            print("\n%s = SteamIntEnum(%r, {" % (class_name, class_name))
            for ikey, ivalue in attrs.items():
                print("    %r: %r," % (ikey, ivalue))
            print("    })")
        else:
            print("\nclass {class_name}(SteamIntEnum):".format(class_name=class_name))
            for ikey, ivalue in attrs.items():
                print("    {} = {}".format(ikey, ivalue))

print("\n__all__ = [")

for class_name in sorted(classes, key=lambda x: x.lower()):
    print("    %r," % class_name)

print("    ]")
