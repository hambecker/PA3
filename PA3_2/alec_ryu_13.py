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

        self.servers = [{'ip': "10.0.0.5",
                         'mac': "00:00:00:00:00:05",
                         'port': 5,
                         'ip_spoof': ""},
                        {'ip': "10.0.0.6",
                         'mac': "00:00:00:00:00:06",
                         'port': 6,
                         'ip_spoof': ""}]

        self.clients = [{'ip': "10.0.0.1", 'mac': "00:00:00:00:00:01", 'port': 1},
                        {'ip': "10.0.0.2", 'mac': "00:00:00:00:00:02", 'port': 2},
                        {'ip': "10.0.0.3", 'mac': "00:00:00:00:00:03", 'port': 3},
                        {'ip': "10.0.0.4", 'mac': "00:00:00:00:00:04", 'port': 4}]

        self.clients_new = {"10.0.0.1": "00:00:00:00:00:01",
                            "10.0.0.2": "00:00:00:00:00:02",
                            "10.0.0.3": "00:00:00:00:00:03",
                            "10.0.0.4": "00:00:00:00:00:04"}

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

        dst_mac = eth.dst
        src_mac = eth.src

        # Not sure if this means anything all data paths from h1-h4 are 1
        dpid = datapath.id
        print("datapathid: " + str(dpid))
        print(datapath)
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src_mac, dst_mac, in_port)

        # ports are the host numbers
        # scr and dst are MAC address
        # dst always comes in as FF:FF:FF:FF:FF:FF

        print("packet in dpid: " + str(dpid) + " src: " + src_mac + " dst: " + dst_mac + " in_port: " + str(in_port))

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src_mac] = in_port

        # Intercept an ARP request
        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            print('In ARP received')
            arp_protocol = pkt.get_protocol(arp.arp)
            print(eth)

            # eth addresses are mac addresses
            # Handle a client ARP request
            if eth.src == self.clients[0]['mac'] \
                    or eth.src == self.clients[1]['mac'] \
                    or eth.src == self.clients[2]['mac']\
                    or eth.src == self.clients[3]['mac']:
                print('ARP request from client')

                # Build packet to send back to client
                e = ethernet.ethernet(dst=src_mac,
                                      src=dst_mac,
                                      ethertype=ether.ETH_TYPE_ARP)
                a = arp.arp(hwtype=1, proto=0x0800, hlen=6, plen=4, opcode=arp.ARP_REPLY,
                            src_mac=self.servers[self.current_server]['mac'],
                            src_ip=arp_protocol.dst_ip,
                            dst_mac=arp_protocol.src_mac, dst_ip=arp_protocol.src_ip)
                p = packet.Packet()
                p.add_protocol(e)
                p.add_protocol(a)
                p.serialize()
                p_copy = packet.Packet(p.data[:])

                # find the port of the current server that can handle a request
                out_port = self.servers[self.current_server]['port']

                # save the ip that the server is suppose to look like it is coming from
                self.servers[self.current_server]['ip_spoof'] = arp_protocol.dst_ip

                # install a flow to avoid packet_in next time
                set_ip = parser.OFPActionSetField(ipv4_dst=self.servers[self.current_server]['ip'])
                actions = [set_ip, parser.OFPActionOutput(out_port)]
                if out_port != ofproto.OFPP_FLOOD:
                    print('installing the flow table for client')
                    match = parser.OFPMatch(in_port=in_port,
                                            ipv4_dst=arp_protocol.dst_ip,
                                            eth_dst=self.servers[self.current_server]['mac'],
                                            eth_type=ether_types.ETH_TYPE_IP)
                    # verify if we have a valid buffer_id, if yes avoid to send both
                    # flow_mod & packet_out
                    if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                        self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                    else:
                        self.add_flow(datapath, 1, match, actions)

                # update the current server so it sends to another server
                if self.current_server == 0:
                    self.current_server = 1
                elif self.current_server == 1:
                    self.current_server = 0

                data = None

                if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                    data = p_copy.data
                    print("got data to send back to client")

                # send the message back to the client
                actions = [parser.OFPActionOutput(ofproto.OFPP_IN_PORT)]
                out = parser.OFPPacketOut(datapath=datapath,  buffer_id=ofproto.OFP_NO_BUFFER,
                                          in_port=in_port, actions=actions, data=data)
                datapath.send_msg(out)

                return

            # handle the ARP request for if a server is sending one in
            elif eth.src == self.servers[0]['mac'] or eth.src == self.servers[1]['mac']:
                print('ARP request from server')

                # Create an ARP Reply packet
                e = ethernet.ethernet(dst=eth.src,
                                      src=eth.dst,
                                      ethertype=ether.ETH_TYPE_ARP)
                self.logger.info(e)
                a = arp.arp(hwtype=1, proto=0x0800, hlen=6, plen=4, opcode=arp.ARP_REPLY,
                            src_mac=self.clients_new[arp_protocol.dst_ip],
                            src_ip=arp_protocol.dst_ip,
                            dst_mac=arp_protocol.src_mac, # need to change this
                            dst_ip=arp_protocol.src_ip)

                p = packet.Packet()
                p.add_protocol(e)
                p.add_protocol(a)
                p.serialize()

                # Extract the correct client number in order to get the correct client data
                client_num = 0
                p_copy = packet.Packet(p.data[:])
                if arp_protocol.dst_ip == self.clients[0]['ip']:
                    client_num = 0
                elif arp_protocol.dst_ip == self.clients[1]['ip']:
                    client_num = 1
                elif arp_protocol.dst_ip == self.clients[2]['ip']:
                    client_num = 2
                elif arp_protocol.dst_ip == self.clients[3]['ip']:
                    client_num = 3

                # Get the proper server number
                if arp_protocol.src_ip == self.servers[0]['ip']:
                    server_num = 0
                else:
                    server_num = 1

                # install a flow to avoid packet_in next time
                out_port = self.clients[client_num]['port']

                # get the ip back from the server data that it supposed to be responding from
                set_ip = parser.OFPActionSetField(ipv4_src=self.servers[server_num]['ip_spoof'])

                # create a flow table entry
                actions = [set_ip, parser.OFPActionOutput(out_port)]
                if out_port != ofproto.OFPP_FLOOD:
                    match = parser.OFPMatch(in_port=in_port,
                                            ipv4_dst=self.clients[client_num]['ip'],
                                            eth_dst=self.clients[client_num]['mac'],
                                            eth_type=ether_types.ETH_TYPE_IP)
                    print('installing the flow table for server')
                    # verify if we have a valid buffer_id, if yes avoid to send both
                    # flow_mod & packet_out
                    if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                        self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                    else:
                        self.add_flow(datapath, 1, match, actions)
                data = None

                # Send the ARP response back to the client
                if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                    data = p_copy.data
                    print("got data to send back to client")
                actions = [parser.OFPActionOutput(ofproto.OFPP_IN_PORT)]
                out = parser.OFPPacketOut(datapath=datapath,
                                          buffer_id=ofproto.OFP_NO_BUFFER,
                                          in_port=in_port,
                                          actions=actions,
                                          data=data)
                datapath.send_msg(out)
                return

        if dst_mac in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst_mac]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst_mac, eth_src=src_mac)
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
