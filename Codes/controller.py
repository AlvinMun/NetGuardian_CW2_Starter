#!/usr/bin/env python3
"""NetGuardian Tasks 2 and 4: Ryu OpenFlow 1.3 controller.

Environment variables:
  NG_FLOW_WINDOW=5       detection window in seconds
  NG_FLOW_THRESHOLD=4    suspicious distinct h8->h7 TCP flows per second
  NG_MITIGATION_TIMEOUT=15
"""
import os
import time
import csv
import sys
from datetime import datetime, timezone
from collections import defaultdict
from pathlib import Path
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, tcp, ether_types
from ryu.lib import hub
sys.path.insert(0, str(Path(__file__).resolve().parent))
from flow_detection import FlowRateDetector

H8_IP = "10.0.3.99"
H7_IP = "10.0.3.40"
FLOW_WINDOW = float(os.getenv("NG_FLOW_WINDOW", "5"))
FLOW_THRESHOLD = float(os.getenv("NG_FLOW_THRESHOLD", "4"))
MITIGATION_TIMEOUT = int(os.getenv("NG_MITIGATION_TIMEOUT", "15"))
SECURITY_LOG = Path(os.getenv("NG_SECURITY_LOG", "data/security_events.csv"))
IDLE_TIMEOUT = 5
if MITIGATION_TIMEOUT <= 0:
    raise ValueError("NG_MITIGATION_TIMEOUT must be positive")

class NetGuardianController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.mac_to_port = defaultdict(dict)
        self.flow_detector = FlowRateDetector(FLOW_WINDOW, FLOW_THRESHOLD)
        self.mitigation_until = 0
        self.datapaths = {}
        self.packet_in_flows = {}
        self.previous_h8_flows = set()
        self.pending_flow_stats = defaultdict(list)
        self.stats_thread = hub.spawn(self.request_flow_stats)

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
        # h6 and h7 are both attached to s3 (DPID 3), so enforce the guest
        # policy before the first guest packet can be forwarded.
        if dp.id == 3:
            self.drop_ipv4(dp, "10.0.3.31", H7_IP, priority=400)
        self.logger.info("Switch %s connected using OpenFlow 1.3", dp.id)

    def request_flow_stats(self):
        """Poll s3 so IDS counts packet-in candidates confirmed in switch state."""
        while True:
            for dp in list(self.datapaths.values()):
                if dp.id != 3:
                    continue
                parser, ofp = dp.ofproto_parser, dp.ofproto
                request = parser.OFPFlowStatsRequest(
                    datapath=dp, flags=0, table_id=ofp.OFPTT_ALL,
                    out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY,
                    cookie=0, cookie_mask=0, match=parser.OFPMatch())
                dp.send_msg(request)
            hub.sleep(1)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply(self, ev):
        msg, dp = ev.msg, ev.msg.datapath
        body = self.pending_flow_stats[dp.id]
        body.extend(msg.body)
        if msg.flags & dp.ofproto.OFPMPF_REPLY_MORE:
            return
        self.pending_flow_stats[dp.id] = []
        if dp.id != 3:
            return

        now = time.monotonic()
        observed = {flow: stamp for flow, stamp in self.packet_in_flows.items()
                    if now - stamp <= FLOW_WINDOW}
        self.packet_in_flows = observed
        current = {}
        for stat in body:
            match = stat.match
            if (match.get("ipv4_src") != H8_IP or
                    match.get("ipv4_dst") != H7_IP or
                    match.get("ip_proto") != 6 or
                    match.get("tcp_src") is None or
                    match.get("tcp_dst") is None):
                continue
            flow = (H8_IP, H7_IP, match.get("tcp_src"),
                    match.get("tcp_dst"), 6)
            current[flow] = stat

        new_flows = set(current) - self.previous_h8_flows
        active_count = len(current)
        for flow in new_flows:
            packet_in_time = self.packet_in_flows.pop(flow, None)
            if packet_in_time is not None and now - packet_in_time <= FLOW_WINDOW:
                self.check_new_flow_rate(dp, flow, active_count)
        self.previous_h8_flows = set(current)

    def add_flow(self, dp, priority, match, actions, idle_timeout=IDLE_TIMEOUT,
                 hard_timeout=0):
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        instructions = ([parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
                        if actions else [])
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

    def log_security_event(self, flow, observation, detected, active_flows):
        """Append every packet-in flow confirmed by an OpenFlow stats reply."""
        SECURITY_LOG.parent.mkdir(parents=True, exist_ok=True)
        write_header = not SECURITY_LOG.exists() or SECURITY_LOG.stat().st_size == 0
        with SECURITY_LOG.open("a", newline="") as event_file:
            writer = csv.writer(event_file)
            if write_header:
                writer.writerow(("timestamp_utc", "source_host", "source_ip",
                                 "destination_ip", "source_port", "destination_port",
                                 "protocol", "window_seconds", "new_flows_in_window",
                                 "measured_flows_per_second", "threshold_flows_per_second",
                                 "active_h8_h7_flows", "alert", "action"))
            writer.writerow((
                datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
                "h8", flow[0], flow[1], flow[2], flow[3], flow[4],
                observation.window_seconds, observation.flow_count,
                "{:.3f}".format(observation.measured_rate),
                "{:.3f}".format(observation.threshold),
                active_flows,
                str(observation.suspicious).lower(),
                "DROP_REQUESTED" if detected else "OBSERVED",
            ))

    def check_new_flow_rate(self, dp, flow, active_flows):
        observation = self.flow_detector.observe(flow, time.monotonic())
        if observation is None:
            return False

        now = time.time()
        detected = observation.suspicious and now >= self.mitigation_until
        if detected:
            self.mitigation_until = now + MITIGATION_TIMEOUT
            self.drop_ipv4(dp, H8_IP, H7_IP, priority=500,
                           hard_timeout=MITIGATION_TIMEOUT)
            self.log_security_event(flow, observation, True, active_flows)
            self.logger.warning(
                "SECURITY_ALERT timestamp=%.3f source_host=h8 source_ip=%s "
                "measured_rate=%.2f flows_per_second threshold=%.2f "
                "new_flows=%s window_seconds=%.2f mitigation_timeout=%s",
                now, H8_IP, observation.measured_rate, FLOW_THRESHOLD,
                observation.flow_count, FLOW_WINDOW, MITIGATION_TIMEOUT)
            return True
        self.log_security_event(flow, observation, False, active_flows)
        return False

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
        if ip_pkt and tcp_pkt:
            flow = self.five_tuple(ip_pkt, tcp_pkt)
            if ip_pkt.src == H8_IP and ip_pkt.dst == H7_IP:
                # The later s3 flow-stat reply confirms whether this Packet_In
                # resulted in a five-tuple forwarding entry before it is counted.
                self.packet_in_flows[flow] = time.monotonic()
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
