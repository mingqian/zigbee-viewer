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

import argparse
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
        logging.debug('node: %#x' % source)
    if destination not in nodes and destination < 0xfff8:
        nodes.append(destination)
        logging.debug('node: %#x' % destination)
    if source < 0xfff8 and destination < 0xfff8:
        link = (source, destination)
        if link not in links:
            links.append(link)
            logging.info('link: %#x <-> %#x' % (source, destination))


def update_net_json():
    """
    Create the network JSON using hte module variables.
    """
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


def main(pcap):
    """
    Main function parsing the input pcap. the argument is the file object not
    the file path.
    Use scapy to read this pcap.

       :parameter pcap: File object of the PCAP to parse, not the path.
    """
    packets = rdpcap(pcap.name)
    for packet in packets:  # Iterate over the PCAP
        try:
            update_from_route_record(packet[ZigbeeNWK].source,
                                     packet[ZigbeeNWK].destination)
        except IndexError as error:
            logging.debug(
                """Could not parse Zigbee frame %s
                \tFollowing error wa raised %s""" % (
                    packet, error
                )
            )
    update_net_json()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='Turn a PCAP to the corresponding network.json'
    )
    parser.add_argument('infile',
                        nargs='?',
                        type=argparse.FileType('r'),
                        default=sys.stdin,
                        help='Input PCAP file')
    args = parser.parse_args()
    main(args.infile)
