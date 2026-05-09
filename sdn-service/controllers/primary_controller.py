# -*- coding: utf-8 -*-

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types, ipv4
import redis


class PrimaryController(app_manager.RyuApp):
    """
    Primary Controller (Traffic Manager)

    Role:
    - Pure L2 learning switch
    - Handles NORMAL traffic only
    - Checks Redis for blocked IPs
    - SecurityController may override using higher-priority rules
    """

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(PrimaryController, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

        # FIX 5: wrap Redis connection in try/except with graceful fallback.
        # Previously an unhandled ConnectionRefusedError here crashed the
        # controller on cold start since primary-controller has no depends_on
        # and Redis may not be ready yet.
        try:
            self.redis = redis.Redis(
                host='redis-db', port=6379, db=0,
                socket_connect_timeout=3
            )
            self.redis.ping()
            self.use_redis = True
            self.logger.info("[Primary] ✅ Redis connected")
        except Exception as e:
            self.logger.warning(
                "[Primary] ⚠️  Redis unavailable (%s) — blacklist checks disabled", e
            )
            self.redis      = None
            self.use_redis  = False

        self.logger.info("[Primary] Traffic Controller Online")

    # ---------------- SWITCH INIT ----------------
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto  = datapath.ofproto
        parser   = datapath.ofproto_parser

        match   = parser.OFPMatch()
        actions = [
            parser.OFPActionOutput(
                ofproto.OFPP_CONTROLLER,
                ofproto.OFPCML_NO_BUFFER
            )
        ]

        self.add_flow(datapath, priority=0, match=match, actions=actions)
        self.logger.info("[Primary] Table-miss flow installed")

    # ---------------- FLOW INSTALL ----------------
    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser  = datapath.ofproto_parser

        inst = [
            parser.OFPInstructionActions(
                ofproto.OFPIT_APPLY_ACTIONS,
                actions
            )
        ]

        if buffer_id:
            mod = parser.OFPFlowMod(
                datapath=datapath,
                buffer_id=buffer_id,
                priority=priority,
                match=match,
                instructions=inst
            )
        else:
            mod = parser.OFPFlowMod(
                datapath=datapath,
                priority=priority,
                match=match,
                instructions=inst
            )

        datapath.send_msg(mod)

    # ---------------- PACKET HANDLER ----------------
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg      = ev.msg
        datapath = msg.datapath
        ofproto  = datapath.ofproto
        parser   = datapath.ofproto_parser
        in_port  = msg.match["in_port"]

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        # Ignore LLDP
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        # Check if source IP is blocked
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if ip_pkt:
            src_ip = ip_pkt.src

            # FIX 5: guard every Redis call so a mid-run Redis failure does
            # not throw an unhandled exception and crash the Ryu event loop.
            is_blocked = False
            if self.use_redis and self.redis is not None:
                try:
                    is_blocked = bool(
                        self.redis.exists("blacklist:{}".format(src_ip))
                    )
                except Exception as e:
                    self.logger.warning("[Primary] Redis check failed: %s", e)

            if is_blocked:
                self.logger.warning(
                    "[Primary] Dropping packet from blacklisted IP: %s", src_ip
                )
                match   = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip)
                actions = []
                self.add_flow(datapath, priority=50, match=match, actions=actions)
                return

        dst  = eth.dst
        src  = eth.src
        dpid = datapath.id

        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(
                in_port=in_port,
                eth_src=src,
                eth_dst=dst
            )

            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(
                    datapath,
                    priority=1,
                    match=match,
                    actions=actions,
                    buffer_id=msg.buffer_id
                )
                return
            else:
                self.add_flow(
                    datapath,
                    priority=1,
                    match=match,
                    actions=actions
                )

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data
        )

        datapath.send_msg(out)