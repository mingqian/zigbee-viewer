#!/usr/bin/env python

# Copyright (C) 2018  Mingqian Han
# Author: Mingqian (mq_han@hotmail.com)
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import sys
from scapy.config import Conf
from scapy.utils import rdpcap
from scapy.layers.dot15d4 import Dot15d4FCS, Dot15d4Data
from scapy.layers.zigbee import ZigbeeNWK, ZigbeeSecurityHeader
from Cryptodome.Cipher import AES
from binascii import unhexlify
import struct
from struct import pack, unpack
import json

# Zigbee 3.0 uses this security level
security_level = 0x05 # ENC-MIC-32
key_str_len = 16 * 2
mic_len = 4
nwk_keys = set()
nodes = dict()
links = dict()


cmd_route_record = 0x05
route_record_processed = 0


def update_nwk_keys(key_str):
    if len(key_str) == key_str_len:
        nwk_keys.add(unhexlify(key_str))


def decrypt(pkt):
    nwk_hdr = pkt[ZigbeeNWK].raw_packet_cache

    if ZigbeeSecurityHeader in pkt:
        ext_src = pkt[ZigbeeSecurityHeader].source
        sec_fc = pkt[ZigbeeSecurityHeader].fc
        sec_cntl = (pkt[ZigbeeSecurityHeader].extended_nonce << 5) |\
                (pkt[ZigbeeSecurityHeader].key_type << 3) |\
                security_level
        key_seqnum = pkt[ZigbeeSecurityHeader].key_seqnum
        if key_seqnum is None:
            aux_hdr = pack('<BIQ', sec_cntl, sec_fc, ext_src)
        else:
            aux_hdr = pack('<BIQB', sec_cntl, sec_fc, ext_src, key_seqnum)

        a = nwk_hdr + aux_hdr
        nonce = pack('<QIB', ext_src, sec_fc, sec_cntl)
        # TODO:
        # The pcap should be DLT_IEEE802_15_4_NOFCS(?), but scapy dissects
        # like DLT_IEEE802_15_4_WITHFCS.
        # Temporary workaround here.
        # Maybe add --withfcs command line argument?
        tag = pkt.data[-2:] + pack('<H', pkt[Dot15d4FCS].fcs)
        # print('nwk_hdr: {}'.format(nwk_hdr.hex()))
        # print('aux_hdr: {}'.format(aux_hdr.hex()))
        # print('nonce: {}'.format(nonce.hex()))
        # print('tag: {}'.format(tag.hex()))
        for k in nwk_keys:
            try:
                cipher = AES.new(key=k, mode=AES.MODE_CCM, nonce=nonce, mac_len=mic_len)
                cipher.update(a)
                # print('from {} bytes: {}'.format(len(pkt.data[:-2]), pkt.data[:-2].hex()))
                decrypted_data = cipher.decrypt_and_verify(pkt.data[:-2], tag)
                # print('to {} bytes: {}'.format(len(decrypted_data), decrypted_data.hex()))
                return decrypted_data
            except ValueError as e:
                # print(e)
                continue
        return None



def update_nodes(panid, addr):
    global nodes

    if addr < 0xfff8:
        if panid not in nodes.keys():
            nodes[panid] = {addr}
        else:
            nodes[panid].add(addr)


def update_links_route_record(panid, source, data):
    global links

    relay_count = data[0]
    tmp = []
    if relay_count > 0:
        relays = data[1:]
        for i in range(relay_count):
            relay = unpack("<H", relays[2 * i: 2 * i + 2])[0]
            tmp.append(relay)
            if i == 0:
                link = (source, relay)
            else:
                link = (tmp[-2], relay)

            if panid not in links.keys():
                links[panid] = {link}
            else:
                links[panid].add(link)


def update_links(panid, source, data):
    global route_record_processed
    cmd_id = data[0]

    if cmd_id == cmd_route_record:
        update_links_route_record(panid, source, data[1:])
        route_record_processed += 1


def update_netjson_single_pan(panid, nodes, links):
    nodes_desc = []
    links_desc = []

    for n in nodes:
        nodes_desc.append({'id': hex(n)})

    if links is not None:
        for link in links:
            links_desc.append({'source': hex(link[0]),
                               'target': hex(link[1]),
                               'cost': 1.0})

    fname = 'pan_' + hex(panid) + '.json'
    with open(fname, 'w+') as f:
        f.write(json.dumps({
                            'type': 'NetworkGraph',
                            'label': 'ZigBee',
                            'protocol': 'OLSR',
                            'version': '0.6.6.2',
                            'metric': 'ETX',
                            'nodes': nodes_desc,
                            'links': links_desc
                            })
                )


def update_netjson():
    global nodes
    global links

    for panid in nodes.keys():
        if panid in links.keys():
            update_netjson_single_pan(panid, nodes[panid], links[panid])
        else:
            update_netjson_single_pan(panid, nodes[panid], None)
        pan_nodes = nodes[panid]



def usage(cmd):
    print('*' * 50)
    print('''A tool to visualize zigbee mesh network.
    {} <pcap/pcapng file> <nwk key file>
    '''.format(cmd))


def main(argv):
    Conf.dot15d4_protocol = "zigbee"
    Conf.load_layers = ['dot15d4', 'zigbee']

    try:
        with open(argv[2]) as f:
            for line in f:
                update_nwk_keys(line.strip())
    except IOError:
        print('ERROR: failed to open nwk key file')
        usage(argv[0])
        exit()

    try:
        pkts = rdpcap(argv[1])
    except IOError:
        print('ERROR: failed to open pcap/pcapng file')
        usage(argv[0])
        exit()

    print('Processing {} packets ...'.format(len(pkts)))
    decrypt_ok = 0
    decrypt_fail = 0
    zbee_nwk_processed = 0
    for (i, p) in enumerate(pkts):
        if ZigbeeNWK in p:
            try:
                # ignore ZGP packets
                if p[Dot15d4FCS].fcf_srcaddrmode != 2:
                    continue
                zbee_nwk_processed += 1
                panid = p[Dot15d4Data].dest_panid
                source = p[ZigbeeNWK].source
                update_nodes(panid, source)
                update_nodes(panid, p[ZigbeeNWK].destination)
                decrypted_data = decrypt(p)
                if decrypted_data is not None:
                    decrypt_ok += 1
                    update_links(panid, source, decrypted_data)
                else:
                    decrypt_fail += 1
                    # print('{}: decrypt error'.format(i))
                    # TODO:
                    # some undecrypted packets can actually be
                    # decrypted in Wireshark. Need to check.
            except (IndexError, struct.error) as e:
                print('{} exception: {}'.format(i, str(e)))
                p.show()
                exit()

    update_netjson()
    print('Processed {} Zigbee NWK packets!'.format(zbee_nwk_processed))
    print('  --- {} packets decrypted, {} packets undecrypted!'.format(decrypt_ok, decrypt_fail))
    print('  --- Processed {} route records!'.format(route_record_processed))


if __name__ == "__main__":
    if len(sys.argv) < 3:
        usage(sys.argv[0])
        exit()
    main(sys.argv)
