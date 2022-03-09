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

import json
import logging
import sys

from scapy.all import rdpcap
from scapy.config import conf
from scapy.layers.zigbee import (
    ZigbeeNWK
)

logging.basicConfig(format='%(asctime)s %(message)s', level=logging.DEBUG)

conf.dot15d4_protocol = "zigbee"
nodes = []
links = []


def update_from_route_record(source, destination):
    """
    Source and destination are nodes. Links are a tuple made of those two.
    It exclude all types of broadcast communication are exclude. See the note
    containing an extract of the 3.6.5 paragraph listing the different address.

       :source: Source address of the Zigbee frame
       :destination:  Destination address of the Zigbee frame

    .. note::

       3.6.5 Broadcast Communication

          - 0xffff: All devices in PAN
          - 0xfffe: Reserved
          - 0xfffd: macRxOnWhenIdle = TRUE
          - 0xfffc: All routers and coordinator
          - 0xfffb: Low power routers only
          - 0xfff8 - 0xfffa: Reserved
    """
    if source not in nodes and source < 0xfff8:
        nodes.append(source)
        logging.debug('node: %#x') % source
    if destination not in nodes and destination < 0xfff8:
        nodes.append(destination)
        logging.debug('node: %#x') % destination
    if source < 0xfff8 and destination < 0xfff8:
        link = (source, destination)
        if link not in links:
            links.append(link)
            logging.info('link: %#x <-> %#x') % (source, destination)


def update_netjson():
    nodes_desc = []
    links_desc = []

    for n in nodes:
        nodes_desc.append({'id': hex(n)})

    for link in links:
        links_desc.append({'source': hex(link[0]),
                           'target': hex(link[1]),
                           'cost': 1.0})

    with open('netjson.json', 'w+') as net_json_file:
        net_json_file.write(
            json.dumps({
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
    logging.warning('*' * 50)
    logging.warning('''A tool to visualize zigbee mesh network.\n
    %s <pcap/pcapng file> <nwk key file>
    ''') % cmd


def main(argv):
    try:
        packets = rdpcap(argv[1])
    except IOError:
        logging.error('failed to open pcap/pcapng file')
        usage(argv[0])
        exit()

    network_key = argv[2]
    for packet in packets:
        try:
            update_from_route_record(packet[ZigbeeNWK].source,
                                     packet[ZigbeeNWK].destination)
        except IndexError as error:
            logging.debug(
                "Could not parse Zigbee frame %s\n\tFollowing error wa raised %s" % (
                    packet, error
                )
            )
    update_netjson()


if __name__ == "__main__":
    if len(sys.argv) < 3:
        usage(sys.argv[0])
        exit()
    main(sys.argv)
