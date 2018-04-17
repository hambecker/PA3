# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import arp
from ryu.ofproto import ether


class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

        self.servers = [{'ip': "10.0.0.5", 'mac': "00:00:00:00:00:05"},
                        {'ip': "10.0.0.6", 'mac': "00:00:00:00:00:06"}]

        self.clients = [{'ip': "10.0.0.1", 'mac': "00:00:00:00:00:01"},
                        {'ip': "10.0.0.2", 'mac': "00:00:00:00:00:02"},
                        {'ip': "10.0.0.3", 'mac': "00:00:00:00:00:03"},
                        {'ip': "10.0.0.4", 'mac': "00:00:00:00:00:04"}]

        self.current_server = 0

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        msg = ev.msg
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.

        match = parser.OFPMatch()

        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
            # handle the arp request
        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            print('In ARP received')
            arp_protocol = pkt.get_protocol(arp.arp)
            print(eth)

            # eth addresses are mac addresses
            if eth.src == self.clients[0]['mac'] \
                    or eth.src == self.clients[1]['mac'] \
                    or eth.src == self.clients[2]['mac']\
                    or eth.src == self.clients[3]['mac']:
                print('ARP request from client')
                e = ethernet.ethernet(dst=eth.src,
                                      src=eth.dst,
                                      ethertype=ether.ETH_TYPE_ARP)
                a = arp.arp(hwtype=1, proto=0x0800, hlen=6, plen=4, opcode=2,
                            src_mac=self.servers[self.current_server]['mac'],
                            src_ip=self.servers[self.current_server]['ip'],
                            dst_mac=arp_protocol.src_mac, dst_ip=arp_protocol.src_ip)
                p = packet.Packet()
                p.add_protocol(e)
                p.add_protocol(a)
                p.serialize()
                p_copy = packet.Packet(p.data[:])
                if self.current_server == 0:
                    self.current_server = 1
                elif self.current_server == 1:
                    self.current_server = 0
            elif eth.src == self.servers[0]['mac'] or eth.src == self.servers[1]['mac']:
                print('ARP request from server')
                e = ethernet.ethernet(dst=eth.src,
                                      src=eth.dst,
                                      ethertype=ether.ETH_TYPE_ARP)
                a = arp.arp(hwtype=1, proto=0x0800, hlen=6, plen=4, opcode=2,
                            src_mac=arp_protocol.dst_mac,
                            src_ip=arp_protocol.dst_mac,
                            dst_mac=arp_protocol.src_mac,
                            dst_ip=arp_protocol.src_ip)
                p = packet.Packet()
                p.add_protocol(e)
                p.add_protocol(a)
                p.serialize()
                p_copy = packet.Packet(p.data[:])

        dst = eth.dst
        src = eth.src

        # Not sure if this means anything all data paths from h1-h4 are 1
        dpid = datapath.id
        print("datapathid: " + str(dpid))
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)
        print("packet in dpid: %s src: %s dst: %s in_port:%s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
