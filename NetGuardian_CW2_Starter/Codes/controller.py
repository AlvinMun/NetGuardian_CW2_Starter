#!/usr/bin/env python3
"""NetGuardian Tasks 2 and 4: Ryu OpenFlow 1.3 controller.

Environment variables:
  NG_FLOW_WINDOW=5       detection window in seconds
  NG_FLOW_THRESHOLD=4    suspicious distinct h8->h7 TCP flows per second
  NG_MITIGATION_TIMEOUT=15
"""
import os
import time
from collections import defaultdict
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, tcp, ether_types
from ryu.lib import hub

H8_IP = "10.0.3.99"
H7_IP = "10.0.3.40"
FLOW_WINDOW = float(os.getenv("NG_FLOW_WINDOW", "5"))
FLOW_THRESHOLD = float(os.getenv("NG_FLOW_THRESHOLD", "4"))
MITIGATION_TIMEOUT = int(os.getenv("NG_MITIGATION_TIMEOUT", "15"))
IDLE_TIMEOUT = 5

class NetGuardianController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.mac_to_port = defaultdict(dict)
        self.window_started = time.monotonic()
        self.window_flows = set()
        self.mitigation_until = 0
        self.datapaths = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features(self, ev):
        dp = ev.msg.datapath
        self.datapaths[dp.id] = dp
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        # Table-miss: send unknown packets to controller; no idle timeout.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER,
                                          ofp.OFPCML_NO_BUFFER)]
        self.add_flow(dp, 0, match, actions, idle_timeout=0)
        self.logger.info("Switch %s connected using OpenFlow 1.3", dp.id)

    def add_flow(self, dp, priority, match, actions, idle_timeout=IDLE_TIMEOUT,
                 hard_timeout=0):
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        instructions = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=dp, priority=priority, match=match,
                                instructions=instructions,
                                idle_timeout=idle_timeout,
                                hard_timeout=hard_timeout)
        dp.send_msg(mod)

    def drop_ipv4(self, dp, src, dst, priority=300, hard_timeout=0):
        match = dp.ofproto_parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                           ipv4_src=src, ipv4_dst=dst)
        self.add_flow(dp, priority, match, [], idle_timeout=0,
                      hard_timeout=hard_timeout)

    def five_tuple(self, ip_pkt, tcp_pkt):
        return (ip_pkt.src, ip_pkt.dst, tcp_pkt.src_port,
                tcp_pkt.dst_port, 6)

    def check_new_flow_rate(self, dp, flow):
        now = time.monotonic()
        elapsed = now - self.window_started
        # Evaluate a completed observation window, rather than dividing by a
        # near-zero elapsed time (which would falsely alert on the first flow).
        if elapsed >= FLOW_WINDOW:
            rate = len(self.window_flows) / elapsed
            if rate > FLOW_THRESHOLD and time.time() >= self.mitigation_until:
                self.mitigation_until = time.time() + MITIGATION_TIMEOUT
                self.drop_ipv4(dp, H8_IP, H7_IP, priority=500,
                               hard_timeout=MITIGATION_TIMEOUT)
                self.logger.warning(
                    "SECURITY_ALERT timestamp=%.3f source=%s measured_rate=%.2f "
                    "flows_per_second threshold=%.2f mitigation_timeout=%s",
                    time.time(), H8_IP, rate, FLOW_THRESHOLD, MITIGATION_TIMEOUT)
            self.window_flows.clear()
            self.window_started = now
        self.window_flows.add(flow)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        in_port = msg.match["in_port"]
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth is None or eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return
        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            # ARP flooding is required for initial address resolution.
            actions = [parser.OFPActionOutput(ofp.OFPP_FLOOD)]
            out = parser.OFPPacketOut(datapath=dp, buffer_id=msg.buffer_id,
                                      in_port=in_port, actions=actions,
                                      data=msg.data if msg.buffer_id == ofp.OFP_NO_BUFFER else None)
            dp.send_msg(out)
            return

        src, dst = eth.src, eth.dst
        self.mac_to_port[dp.id][src] = in_port
        self.logger.info("MAC_LEARN switch=%s mac=%s port=%s", dp.id, src, in_port)
        out_port = self.mac_to_port[dp.id].get(dst, ofp.OFPP_FLOOD)

        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        if ip_pkt and ip_pkt.src == "10.0.3.31" and ip_pkt.dst == H7_IP:
            # Permanent guest-to-protected-server policy deny.
            self.drop_ipv4(dp, ip_pkt.src, ip_pkt.dst, priority=400)
            return

        if ip_pkt and tcp_pkt:
            flow = self.five_tuple(ip_pkt, tcp_pkt)
            if ip_pkt.src == H8_IP and ip_pkt.dst == H7_IP:
                self.check_new_flow_rate(dp, flow)
                # Do not forward the packet that completes a triggering window.
                if time.time() < self.mitigation_until:
                    return
            # Five-tuple TCP entries ensure each new connection reaches Packet_In.
            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                    ip_proto=6, ipv4_src=ip_pkt.src,
                                    ipv4_dst=ip_pkt.dst,
                                    tcp_src=tcp_pkt.src_port,
                                    tcp_dst=tcp_pkt.dst_port)
        elif ip_pkt:
            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                    ipv4_src=ip_pkt.src, ipv4_dst=ip_pkt.dst)
        else:
            match = parser.OFPMatch(in_port=in_port, eth_src=src, eth_dst=dst)

        actions = [parser.OFPActionOutput(out_port)]
        if out_port != ofp.OFPP_FLOOD:
            self.add_flow(dp, 10, match, actions, idle_timeout=IDLE_TIMEOUT)
        data = msg.data if msg.buffer_id == ofp.OFP_NO_BUFFER else None
        out = parser.OFPPacketOut(datapath=dp, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        dp.send_msg(out)
