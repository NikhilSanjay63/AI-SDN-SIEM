# -*- coding: utf-8 -*-
"""
security_controller.py  —  IMPROVED VERSION
============================================
Improvements over original:
  1. Redis state management  : Flow stats stored in Redis instead of in-memory
                               dict. Controller restarts no longer lose flow
                               history.
  2. Batch inference         : Flows are buffered locally and sent to the AI
                               service in batches (default: 10) via the new
                               /analyze_batch endpoint, cutting REST overhead
                               by ~10×.
  3. Multi-controller ready  : Listens on port 6634 (security-only port) so
                               it can run as a fully independent Docker service
                               alongside the primary controller on port 6633.
"""

import time
import math
import json
import threading
import requests
import redis

from collections import defaultdict

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, tcp, udp

# ══════════════════════════════════════════════════════
#  CONFIG
# ══════════════════════════════════════════════════════
AI_BATCH_URL    = "http://ai-service:5000/analyze_batch"

# Improvement 2 – Batch Inference
BATCH_SIZE      = 10        # send to AI when buffer reaches this size
BATCH_TIMEOUT   = 2.0       # OR when this many seconds have passed (whichever first)

# Packet / time thresholds for when a flow is "ready" to be analysed
PACKET_THRESHOLD = 3
FLOW_TIMEOUT     = 1.0      # seconds

# Improvement 1 – Redis
REDIS_HOST      = "redis-db"
REDIS_PORT      = 6379
REDIS_TTL       = 120       # seconds — flow keys expire automatically

# Improvement 3 – Multi-controller
# Run ryu-manager with --ofp-tcp-listen-port 6634 to separate from primary (6633)
LISTEN_PORT     = 6634
# ══════════════════════════════════════════════════════


class SecurityController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SecurityController, self).__init__(*args, **kwargs)

        self.datapaths = {}

        # ── Improvement 1: Redis client ──────────────────────────────────────
        # Falls back gracefully if Redis is unavailable (e.g. local testing)
        try:
            self.redis = redis.Redis(
                host=REDIS_HOST, port=REDIS_PORT,
                decode_responses=True, socket_connect_timeout=2
            )
            self.redis.ping()
            self.use_redis = True
            self.logger.info("[Security] ✅ Redis connected at %s:%s", REDIS_HOST, REDIS_PORT)
        except Exception as e:
            self.logger.warning("[Security] ⚠️  Redis unavailable (%s) — falling back to in-memory", e)
            self.use_redis = False
            self._local_flows = {}   # fallback in-memory store

        # ── Improvement 2: Batch buffer ──────────────────────────────────────
        self._batch_lock   = threading.Lock()
        self._batch_buffer = []          # list of (payload_dict, datapath) tuples
        self._last_flush   = time.time()

        # Background thread flushes on timeout even when batch isn't full
        self._flush_thread = threading.Thread(
            target=self._batch_flush_loop
        )
        self._flush_thread.daemon = True
        self._flush_thread.start()

        self.logger.info("[Security] Controller started  (port=%s, batch=%s)", LISTEN_PORT, BATCH_SIZE)

    # ══════════════════════════════════════════════════
    #  REDIS HELPERS
    # ══════════════════════════════════════════════════

    def _flow_key(self, fid):
        """Convert 5-tuple to a Redis key string."""
        return "flow:" + ":".join(str(x) for x in fid)

    def _get_flow(self, fid):
        """Load flow state from Redis (or local dict)."""
        if self.use_redis:
            raw = self.redis.get(self._flow_key(fid))
            if raw is None:
                return self._new_flow()
            return json.loads(raw)
        else:
            return self._local_flows.get(fid, self._new_flow())

    def _save_flow(self, fid, flow):
        """Persist flow state to Redis (or local dict) with TTL."""
        if self.use_redis:
            self.redis.setex(
                self._flow_key(fid), REDIS_TTL,
                json.dumps(flow)
            )
        else:
            self._local_flows[fid] = flow

    def _delete_flow(self, fid):
        """Remove a completed flow from Redis (or local dict)."""
        if self.use_redis:
            self.redis.delete(self._flow_key(fid))
        else:
            self._local_flows.pop(fid, None)

    def _new_flow(self):
        """Return a blank flow statistics dict (JSON-serialisable)."""
        return {
            "start":    None,
            "last":     None,
            "iat":      [],
            "pkt_sizes":[],
            "fwd_pkts": 0,
            "fwd_bytes":0,
            "flags":    {"SYN": 0, "ACK": 0, "RST": 0, "PSH": 0, "URG": 0},
            "src_port": 0,
            "dst_port": 0,
            "protocol": 0,
            "src_ip":   None,
            "dst_ip":   None
        }

    # ══════════════════════════════════════════════════
    #  SWITCH SETUP
    # ══════════════════════════════════════════════════

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        self.datapaths[datapath.id] = datapath

        ofproto = datapath.ofproto
        parser  = datapath.ofproto_parser

        # Table-miss: send unmatched packets to this controller
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        mod = parser.OFPFlowMod(
            datapath=datapath, priority=0,
            match=match, instructions=inst
        )
        datapath.send_msg(mod)
        self.logger.info("[Security] Table-miss installed on datapath %s", datapath.id)

    # ══════════════════════════════════════════════════
    #  PACKET HANDLER
    # ══════════════════════════════════════════════════

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg      = ev.msg
        datapath = msg.datapath

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth.ethertype != 0x0800:   # IPv4 only
            return

        ip_pkt  = pkt.get_protocol(ipv4.ipv4)
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        udp_pkt = pkt.get_protocol(udp.udp)

        if not ip_pkt:
            return

        now    = time.time()
        src_ip = ip_pkt.src
        proto  = ip_pkt.proto

        src_port = tcp_pkt.src_port if tcp_pkt else (udp_pkt.src_port if udp_pkt else 0)
        dst_port = tcp_pkt.dst_port if tcp_pkt else (udp_pkt.dst_port if udp_pkt else 0)

        fid  = (src_ip, ip_pkt.dst, src_port, dst_port, proto)
        flow = self._get_flow(fid)   # ← from Redis

        # Initialise new flow
        if flow["start"] is None:
            flow["start"]    = now
            flow["protocol"] = proto
            flow["src_port"] = src_port
            flow["dst_port"] = dst_port
            flow["src_ip"]   = src_ip
            flow["dst_ip"]   = ip_pkt.dst

        if flow["last"] is not None:
            flow["iat"].append(now - flow["last"])

        flow["last"] = now
        pkt_len = len(msg.data)
        flow["pkt_sizes"].append(pkt_len)
        flow["fwd_pkts"]  += 1
        flow["fwd_bytes"] += pkt_len

        if tcp_pkt:
            bits = tcp_pkt.bits
            if bits & tcp.TCP_SYN: flow["flags"]["SYN"] += 1
            if bits & tcp.TCP_ACK: flow["flags"]["ACK"] += 1
            if bits & tcp.TCP_RST: flow["flags"]["RST"] += 1
            if bits & tcp.TCP_PSH: flow["flags"]["PSH"] += 1
            if bits & tcp.TCP_URG: flow["flags"]["URG"] += 1

        # ── Decide whether to trigger AI analysis ────────────────────────────
        elapsed = now - flow["start"] if flow["start"] else 0
        if flow["fwd_pkts"] >= PACKET_THRESHOLD or elapsed >= FLOW_TIMEOUT:
            self._enqueue_for_ai(flow, datapath)
            self._delete_flow(fid)   # clear state — fresh start for next burst
        else:
            self._save_flow(fid, flow)  # ← persist to Redis

    # ══════════════════════════════════════════════════
    #  IMPROVEMENT 2 — BATCH INFERENCE
    # ══════════════════════════════════════════════════

    def _enqueue_for_ai(self, flow, datapath):
        """Add a ready flow to the batch buffer; flush if full."""
        payload = self._build_payload(flow)
        with self._batch_lock:
            self._batch_buffer.append((payload, datapath))
            if len(self._batch_buffer) >= BATCH_SIZE:
                self._flush_batch()

    def _batch_flush_loop(self):
        """Background thread — flush on timeout even if batch isn't full."""
        while True:
            time.sleep(0.5)
            with self._batch_lock:
                if self._batch_buffer and (time.time() - self._last_flush) >= BATCH_TIMEOUT:
                    self._flush_batch()

    def _flush_batch(self):
        """
        Send the current buffer to /analyze_batch in one HTTP call.
        Must be called with self._batch_lock held.
        """
        if not self._batch_buffer:
            return

        batch     = self._batch_buffer[:]
        self._batch_buffer.clear()
        self._last_flush = time.time()

        payloads   = [item[0] for item in batch]
        datapaths  = [item[1] for item in batch]

        self.logger.info("[Batch] Flushing %d flows to AI", len(payloads))

        try:
            r       = requests.post(AI_BATCH_URL, json={"flows": payloads}, timeout=5)
            results = r.json().get("results", [])

            for result, datapath in zip(results, datapaths):
                mitigation = result.get("mitigation")
                if mitigation and mitigation.get("action") == "BLOCK":
                    self.block_ip(datapath, mitigation["target"])

        except Exception as e:
            self.logger.error("[Batch ERROR] %s", e)

    def _build_payload(self, flow):
        """Translate internal flow dict to the JSON schema expected by app.py."""
        iat = flow["iat"]
        iat_mean = sum(iat) / len(iat) if iat else 0.0
        iat_std  = math.sqrt(
            sum((x - iat_mean) ** 2 for x in iat) / len(iat)
        ) if len(iat) > 1 else 0.0
        iat_max  = max(iat) if iat else 0.0

        pkt_sizes = flow["pkt_sizes"]
        pkt_size_avg = sum(pkt_sizes) / len(pkt_sizes) if pkt_sizes else 0.0

        duration = (flow["last"] - flow["start"]) if (flow["last"] and flow["start"]) else 1e-6

        return {
            "flow_id":       flow["src_ip"],
            "src_ip":        flow["src_ip"],
            "dst_ip":        flow.get("dst_ip", "UNKNOWN"),
            "Flow Duration": duration,
            "Flow IAT Mean": iat_mean,
            "Flow IAT Std":  iat_std,
            "Flow IAT Max":  iat_max,
            "Pkt Size Avg":  pkt_size_avg,
            "Tot Fwd Pkts":  flow["fwd_pkts"],
            "TotLen Fwd Pkts": flow["fwd_bytes"],
            "Protocol":      flow["protocol"],
            "Src Port":      flow["src_port"],
            "Dst Port":      flow["dst_port"],
            "SYN Flag Cnt":  flow["flags"]["SYN"],
            "ACK Flag Cnt":  flow["flags"]["ACK"],
            "RST Flag Cnt":  flow["flags"]["RST"],
            "PSH Flag Cnt":  flow["flags"]["PSH"],
            "URG Flag Cnt":  flow["flags"]["URG"]
        }

    # ══════════════════════════════════════════════════
    #  BLOCK LOGIC  (unchanged from original)
    # ══════════════════════════════════════════════════

    def block_ip(self, datapath, ip):
        ofproto = datapath.ofproto
        parser  = datapath.ofproto_parser

        match = parser.OFPMatch(eth_type=0x0800, ipv4_src=ip)
        inst  = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, [])]

        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=65535,
            match=match,
            instructions=inst,
            idle_timeout=300,
            hard_timeout=600
        )
        datapath.send_msg(mod)
        self.logger.warning("[Security] 🚫 BLOCKED IP: %s", ip)
