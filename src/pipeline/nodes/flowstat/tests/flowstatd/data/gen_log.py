#!/usr/bin/env python3
#
# Copyright (c) 2021, SafePoint.  All rights reserved.
#
# SPDX-License-Identifier: LGPL-2.1-only
#

import random
import time
from datetime import datetime, timedelta


def gen_log(n, rps=1000, name=None):
    APP_NAME_LIST = 'afp aimini ajp amazon amazonvideo amqp apple appleicloud appleitunes applejuice applepush applestore armagetron ayiya battlefield bgp bittorrent bjnp checkmk ciscoskinny ciscovpn citrix cloudflare cnn coap collectd corba crossfire csgo datasaver dce_rpc deezer dhcp dhcpv6 diameter direct_download_link directconnect dnp3 dns dnscrypt dnsoverhttps dofus drda dropbox eaq ebay edonkey egp facebook facebookzero fasttrack fiesta fix florensia ftp_control ftp_data git github gmail gnutella google googledocs googledrive googlehangoutduo googlemaps googleplus googleservices gre gtp guildwars h323 halflife2 hotmail hotspotshield http http_activesync http_connect http_download http_proxy hulu iax icecast icmp icmpv6 iflix igmp imap imaps imo instagram ip_in_ip ipp ipsec irc kakaotalk kakaotalk_voice kerberos kontiki lastfm ldap line linkedin lisp llmnr lotusnotes maplestory mdns megaco memcached messenger mgcp microsoft mining modbus mpeg_ts mqtt ms_onedrive msn mssql_tds mysql nestlogsink netbios netflix netflow nfs nintendo noe ntop ntp ocs office365 ookla opendns openft openvpn oracle oscar ospf pando_media_booster pandora pastebin pcanywhere playstation playstore pop3 pops postgresql pplive ppstream pptp ps_vue qq qqlive quic radius rdp redis remotescan rsync rtcp rtmp rtp rtsp rx sap sctp sflow shoutcast signal sip skype skypecall slack smbv1 smbv23 smpp smtp smtps snapchat snmp socks someip sopcast soulseek soundcloud spotify ssdp ssh starcraft stealthnet steam stun syslog targus_dataspeed teamspeak teamviewer telegram telnet teredo tftp thunder tiktok tinc tls tor truphone tuenti tvants tvuplayer twitch twitter ubntac2 ubuntuone unencrypted_jabber unknown upnp usenet vevo vhua viber vmware vnc vrrp warcraft3 waze webex wechat weibo whatsapp whatsappcall whatsappfiles whois_das wikipedia windowsupdate wireguard worldofkungfu worldofwarcraft xbox xdmcp yahoo youtube youtubeupload zattoo zeromq zoom'
    APP_PROTO_LIST = 'FTP_CONTROL POP3 SMTP IMAP DNS IPP HTTP MDNS NTP NetBIOS NFS SSDP BGP SNMP XDMCP SMBv1 Syslog DHCP'
    APP_TYPE_LIST = 'chat cloud collaborative database datatransfer download email filesharing game media music network productivity remoteaccess rpc shopping socialnetwork softwareupdate streaming system video voip vpn web'

    APP_NAME_LIST = APP_NAME_LIST.split() + ['']
    APP_PROTO_LIST = APP_PROTO_LIST.split() + ['']
    APP_TYPE_LIST = APP_TYPE_LIST.split() + ['']

    now = datetime.now() - timedelta(seconds=n)

    if name is None:
        name = f'{n}.log'

    with open(name, 'w') as f:
        for i in range(n // rps):
            logs = [
                f'date={now.strftime("%Y-%m-%d")} '
                f'time={now.strftime("%H:%M:%S")} '
                f'timestamp={int(now.timestamp())} tz="+07" '
                f'session_id={j} '
                f'src_addr=192.168.100.{random.randint(1, 255)} '
                f'src_port={random.randint(30000, 60000)} '
                f'dst_addr=192.168.200.{random.randint(1, 255)} '
                f'dst_port={random.randint(30000, 60000)} '
                f'in_bytes={random.randint(1, 1500)} '
                f'in_pkts={random.randint(1, 15)} '
                f'protocol={random.randint(1, 100)} '
                f'out_bytes={random.randint(1, 1500)} '
                f'out_pkts={random.randint(1, 15)} '
                f'app_name={random.choice(APP_NAME_LIST)} '
                f'app_proto={random.choice(APP_PROTO_LIST)} '
                f'app_type={random.choice(APP_TYPE_LIST)} '
                f'if_name="dp0p33p1"\n' for j in range(rps)
            ]
            logs = ''.join(logs)
            f.write(logs)
            now += timedelta(seconds=1)
    print('OK')


gen_log(2, 1, name='logintf.log')
