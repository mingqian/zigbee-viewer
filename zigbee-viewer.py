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
from scapy.all import rdpcap, ZigbeeNWK, ZigbeeSecurityHeader
from Cryptodome.Cipher import AES
from binascii import unhexlify
from struct import pack, unpack
import json

nodes = []
links = []


def show_nodes():
    for n in nodes:
        print('node: %#x') % n


def show_links():
    for link in links:
        print('link: %#x <-> %#x') % (link[0], link[1])


def show_network():
    show_nodes()
    show_links()


def update_from_route_record(addr, cnt, data):
    """TODO: Docstring for update_from_route_record.

    :addr: route record source address
    :cnt:  relay count
    :data: relay lists in route record payload

    """
    relays = []

    if addr not in nodes:
        nodes.append(addr)

    for i in range(cnt):
        relay = unpack("<H", data[2 * i: 2 * i + 2])[0]
        relays.append(relay)

        # update nodes in the network
        if relay not in nodes:
            nodes.append(relay)

        # update links in the network
        if i == 0:
            link = (addr, relay)
        else:
            link = (relays[-2], relay)

        if link not in links:
            links.append(link)

        # TODO: find the link to ZC


def update_netjson():
    nodes_desc = []
    links_desc = []

    for n in nodes:
        nodes_desc.append({'id': hex(n)})

    for link in links:
        links_desc.append({'source': hex(link[0]),
                           'target': hex(link[1]),
                           'cost': 1.0})

    with open('netjson.json', 'w+') as f:
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


def usage(cmd):
    print('*' * 50)
    print('''A tool to visualize zigbee mesh network.\n
    %s <pcap/pcapng file> <nwk key file>
    ''') % cmd


def main(argv):
    try:
        pkts = rdpcap(argv[1])
    except IOError:
        print('ERROR: failed to open pcap/pcapng file')
        usage(argv[0])
        exit()

    try:
        with open(argv[2]) as f:
            nwkkey = f.readline()
    except IOError:
        print('ERROR: failed to open nwk key file')
        usage(argv[0])
        exit()

    packageIndex = -1
    for p in pkts:
        try:
            packageIndex += 1
            if ZigbeeNWK in p:
                addr = p[ZigbeeNWK].source
                ext_src = p[ZigbeeSecurityHeader].source
                sec_frm_cnt = p[ZigbeeSecurityHeader].fc
                sec_cntl = 0x2d
                nonce = pack('<QIB', ext_src, sec_frm_cnt, sec_cntl)
                key = unhexlify(nwkkey[:-1])  # ignore last LF
                cipher = AES.new(key, AES.MODE_CCM, nonce)
                decrypted_data = cipher.decrypt(p.data)
                info = unpack('BB', decrypted_data[:2])
                if info[0] == 5 and info[1] > 0:  # route record && relay count > 0
                    update_from_route_record(addr, info[1], decrypted_data[2:])
        except Exception as e:
            print("Exception: "+str(e))
            print()
            print("Package (index in file={:d}) causing the issue:".format(packageIndex))
            print(p.show())
    # show_network()
    update_netjson()


if __name__ == "__main__":
    if len(sys.argv) < 3:
        usage(sys.argv[0])
        exit()
    main(sys.argv)
