"""NetGuardian OpenFlow 1.3 learning switch, monitor and temporary mitigation."""

import math
import os
from pathlib import Path
from tempfile import mkdtemp
import time

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import (
    CONFIG_DISPATCHER, DEAD_DISPATCHER, MAIN_DISPATCHER, set_ev_cls,
)
from ryu.lib import hub
from ryu.lib.packet import ethernet, ether_types, ipv4, packet, tcp
from ryu.ofproto import ofproto_v1_3

from detection import FlowWindow
from monitoring import CsvLog, Monitor, utc_timestamp
from settings import (
    FLOW_IDLE, FORWARD_PRIORITY, HOST_BY_IP, HOST_IP, INGRESS, MITIGATION_COOKIE,
    MITIGATION_PRIORITY, POLICY_PRIORITY, SYN_FLOW_COOKIE,
)

IPV4 = ether_types.ETH_TYPE_IP
TCP = 6
DENIED = HOST_IP["h6"], HOST_IP["h7"]


class NetGuardian(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.datapaths = {}
        self.mac_to_port = {}
        self.pending_blocks = {}
        self.active_blocks = set()
        self.window_seconds = float(os.environ.get("NG_WINDOW", "2"))
        self.threshold = float(os.environ.get("NG_THRESHOLD", "3"))
        self.poll_seconds = float(os.environ.get("NG_POLL", "0.5"))
        self.block_seconds = int(os.environ.get("NG_BLOCK_SECONDS", "5"))
        self.mitigation_enabled = os.environ.get("NG_MITIGATE", "1") == "1"
        if (not all(math.isfinite(value) and value > 0 for value in
                    (self.window_seconds, self.threshold, self.poll_seconds))
                or not 1 <= self.block_seconds <= FLOW_IDLE):
            raise ValueError("Use positive finite timing/threshold values and a 1–5 s block")
        output_setting = os.environ.get("NG_OUTPUT")
        if output_setting:
            output = Path(output_setting)
            output.mkdir(parents=True, exist_ok=True)
        else:
            root = Path("controller-output").resolve()
            root.mkdir(exist_ok=True)
            output = Path(mkdtemp(prefix="run-", dir=root))
        self.logger.info("Results directory: %s", output.resolve())
        self.monitor = Monitor(output)
        self.rates = CsvLog(output / "flow_rates.csv", "timestamp monotonic_s source_ip "
                            "new_flows seconds packet_in_flows stats_flows flows_per_s threshold")
        self.security = CsvLog(output / "security_events.csv", "timestamp monotonic_s "
                               "event source_host source_ip destination_ip switch_id "
                               "flows_per_s threshold block_seconds")
        self.window = FlowWindow(time.monotonic(), self.window_seconds)

    def start(self):
        super().start()
        self.threads.append(hub.spawn(self._sample))

    def _send(self, dp, message):
        dp.set_xid(message)
        dp.send_msg(message)
        return message.xid

    def _flow(self, dp, priority, match, actions=(), idle=0, hard=0, cookie=0, flags=0):
        parser, ofp = dp.ofproto_parser, dp.ofproto
        instructions = []
        if actions:
            instructions.append(parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions))
        return self._send(dp, parser.OFPFlowMod(
            datapath=dp, priority=priority, match=match, instructions=instructions,
            idle_timeout=idle, hard_timeout=hard, cookie=cookie, flags=flags,
        ))

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def configure(self, event):
        dp = event.msg.datapath
        parser, ofp = dp.ofproto_parser, dp.ofproto
        self._flow(dp, POLICY_PRIORITY,
                   parser.OFPMatch(eth_type=IPV4, ipv4_src=DENIED[0], ipv4_dst=DENIED[1]))
        self._flow(dp, 0, parser.OFPMatch(),
                   [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)])
        self.logger.info("s%s: installed permanent guest policy and table-miss", dp.id)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def connection(self, event):
        dp = event.datapath
        if event.state == MAIN_DISPATCHER:
            self.datapaths[dp.id] = dp
            self.mac_to_port[dp.id] = {}
            self.logger.info("s%s connected via OpenFlow 1.3", dp.id)
        elif self.datapaths.get(dp.id) is dp:
            self.datapaths.pop(dp.id)
            self.mac_to_port.pop(dp.id, None)
            self.active_blocks = {ip for ip in self.active_blocks if INGRESS[ip][0] != dp.id}
            self.pending_blocks = {key: block for key, block in self.pending_blocks.items()
                                   if key[0] != dp.id}

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def forward(self, event):
        msg = event.msg
        dp = msg.datapath
        parser, ofp = dp.ofproto_parser, dp.ofproto
        ingress = msg.match["in_port"]
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth is None or eth.ethertype in (ether_types.ETH_TYPE_LLDP, 0x8942):
            return
        ip = pkt.get_protocol(ipv4.ipv4)
        segment = pkt.get_protocol(tcp.tcp)
        if ip and ((ip.src, ip.dst) == DENIED or
                   (ip.dst == HOST_IP["h7"] and ip.src in self.active_blocks)):
            return
        ports = self.mac_to_port.setdefault(dp.id, {})
        if ports.get(eth.src) != ingress:
            ports[eth.src] = ingress
            self.logger.info("MAC learned: s%s %s -> port %s", dp.id, eth.src, ingress)

        observed_syn = (ip and segment and ip.dst == HOST_IP["h7"]
                        and INGRESS.get(ip.src) == (dp.id, ingress)
                        and segment.bits & tcp.TCP_SYN and not segment.bits & tcp.TCP_ACK)
        if observed_syn:
            self.window.observe_packet((ip.src, ip.dst, segment.src_port, segment.dst_port, TCP),
                                       time.monotonic())
        output = ports.get(eth.dst, ofp.OFPP_FLOOD)
        if output == ingress:
            return
        actions = [parser.OFPActionOutput(output)]
        # Exact TCP matches keep a prior connection from hiding later SYNs.
        if output != ofp.OFPP_FLOOD and not (ip and ip.proto == TCP and segment is None):
            fields = dict(in_port=ingress, eth_src=eth.src, eth_dst=eth.dst,
                          eth_type=eth.ethertype)
            if ip:
                fields.update(ipv4_src=ip.src, ipv4_dst=ip.dst, ip_proto=ip.proto)
            if segment:
                fields.update(tcp_src=segment.src_port, tcp_dst=segment.dst_port)
            self._flow(dp, FORWARD_PRIORITY, parser.OFPMatch(**fields), actions,
                       idle=FLOW_IDLE, cookie=SYN_FLOW_COOKIE if observed_syn else 0)
        dp.send_msg(parser.OFPPacketOut(
            datapath=dp, buffer_id=msg.buffer_id, in_port=ingress, actions=actions,
            data=msg.data if msg.buffer_id == ofp.OFP_NO_BUFFER else None,
        ))

    def _sample(self):
        next_poll = time.monotonic()
        while self.is_active:
            now = time.monotonic()
            if now >= next_poll:
                self.monitor.poll(tuple(self.datapaths.values()))
                next_poll = now + self.poll_seconds
            measurements = self.window.close(now)
            for measurement in measurements or ():
                rate = measurement.rate
                source = measurement.source
                self.rates.write([(utc_timestamp(), now, source, measurement.count,
                                   measurement.seconds, measurement.packet_in_count,
                                   measurement.stats_count, rate, self.threshold)])
                dp = self.datapaths.get(INGRESS[source][0])
                if (self.mitigation_enabled and rate > self.threshold
                        and dp is not None and source not in self.active_blocks):
                    self._mitigate(dp, source, rate)
            hub.sleep(max(0, min(next_poll, self.window.started + self.window_seconds)
                          - time.monotonic()))

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats(self, event):
        msg = event.msg
        stats = self.monitor.receive(msg, "flow")
        now = time.monotonic()
        for entry in stats or ():
            if entry.cookie == SYN_FLOW_COOKIE:
                match = entry.match
                key = (match["ipv4_src"], match["ipv4_dst"], match["tcp_src"],
                       match["tcp_dst"], match["ip_proto"])
                age = entry.duration_sec + entry.duration_nsec / 1e9
                self.window.observe_stats(key, now - age)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def port_stats(self, event):
        self.monitor.receive(event.msg, "port")

    def _security_event(self, kind, dp, source, rate=""):
        self.security.write([(utc_timestamp(), time.monotonic(), kind, HOST_BY_IP[source],
                              source, HOST_IP["h7"], dp.id, rate, self.threshold,
                              self.block_seconds)])

    def _mitigate(self, dp, source, rate):
        parser, ofp = dp.ofproto_parser, dp.ofproto
        self._security_event("alert", dp, source, rate)
        self.logger.warning("ALERT %s (%s): %.2f new flows/s, threshold %.2f",
                            HOST_BY_IP[source], source, rate, self.threshold)
        self.active_blocks.add(source)
        flow_id = self._flow(
            dp, MITIGATION_PRIORITY,
            parser.OFPMatch(in_port=INGRESS[source][1], eth_type=IPV4,
                            ipv4_src=source, ipv4_dst=HOST_IP["h7"]),
            idle=FLOW_IDLE, hard=self.block_seconds, cookie=MITIGATION_COOKIE,
            flags=ofp.OFPFF_SEND_FLOW_REM,
        )
        barrier_id = self._send(dp, parser.OFPBarrierRequest(dp))
        self.pending_blocks[dp.id, barrier_id] = source, rate, flow_id

    @set_ev_cls(ofp_event.EventOFPBarrierReply, MAIN_DISPATCHER)
    def confirmed(self, event):
        msg = event.msg
        block = self.pending_blocks.pop((msg.datapath.id, msg.xid), None)
        if block:
            source, rate, _ = block
            self._security_event("drop_confirmed", msg.datapath, source, rate)
            self.logger.info("DROP confirmed on s%s for %s -> h7", msg.datapath.id, source)

    @set_ev_cls(ofp_event.EventOFPErrorMsg, [CONFIG_DISPATCHER, MAIN_DISPATCHER])
    def openflow_error(self, event):
        msg = event.msg
        self.logger.error("OpenFlow error on s%s xid=%s type=%s code=%s",
                          msg.datapath.id, msg.xid, msg.type, msg.code)
        for key, block in list(self.pending_blocks.items()):
            source, rate, flow_id = block
            if key[0] == msg.datapath.id and msg.xid in (key[1], flow_id):
                del self.pending_blocks[key]
                self.active_blocks.discard(source)
                self._security_event("drop_failed", msg.datapath, source, rate)

    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def recover(self, event):
        msg = event.msg
        if msg.cookie == MITIGATION_COOKIE:
            source = msg.match["ipv4_src"]
            self.active_blocks.discard(source)
            self._security_event("drop_removed", msg.datapath, source)
            self.logger.info("DROP removed on s%s for %s -> h7", msg.datapath.id, source)
