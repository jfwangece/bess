# Copyright (c) 2016-2017, Nefeli Networks, Inc.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# * Redistributions of source code must retain the above copyright notice, this
# list of conditions and the following disclaimer.
#
# * Redistributions in binary form must reproduce the above copyright notice,
# this list of conditions and the following disclaimer in the documentation
# and/or other materials provided with the distribution.
#
# * Neither the names of the copyright holders nor the names of their
# contributors may be used to endorse or promote products derived from this
# software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

from test_utils import *


class BessINVISVUDPProxyTest(BessModuleTestCase):
    # Test the packet mangling features with a single rule

    def _test_l4(self, module, l3_orig, l4_orig, allow_client,
                curr_proxy_addr, curr_proxy_port,
                next_proxy_addr, next_proxy_port):

        def _swap_l3(l3):
            ret = l3.copy()
            if type(l3) == scapy.IP:
                ret.src = l3.dst
                ret.dst = l3.src
            return ret

        def _swap_l4(l4):
            ret = l4.copy()
            if type(l4) == scapy.UDP or type(l4) == scapy.TCP:
                ret.sport = l4.dport
                ret.dport = l4.sport
            return ret

        # There are 4 packets in this test:
        # 1. orig, 2. natted, 3. reply, 4. unnatted
        #
        # We're acting as 's0' and 's1' to test 'NAT'
        #
        # +----+    pkt_orig   +------------+     pkt_up      +------+
        # |    |-------------->|            |---------------->|      |
        # | s0 |               |  UDPProxy  |                 | next |
        # |    |<--------------|            |<----------------|      |
        # +----+   pkt_down    +------------+    pkt_repl     +------+

        eth = scapy.Ether(src='02:1e:67:9f:4d:ae', dst='06:16:3e:1b:72:32')
        ip_orig = l3_orig
        ip_up = scapy.IP(src=curr_proxy_addr, dst=next_proxy_addr)
        ip_reply = scapy.IP(src=next_proxy_addr, dst=curr_proxy_addr)
        ip_down = _swap_l3(l3_orig)
        ip_down.src = curr_proxy_addr
        l7 = 'helloworld'

        pkt_orig = eth / ip_orig / l4_orig / l7

        pkt_outs = self.run_module(module, 0, [pkt_orig], [0, 1, 2])

        # UDPProxy's igate and ogate are paired if they have the same index.
        # Thus, ogate 1 and 2 should not receive any packets.
        self.assertEquals(len(pkt_outs[1]), 0)
        self.assertEquals(len(pkt_outs[2]), 0)

        # UDPProxy should drop all non-UDP packets.
        if type(l4_orig) != scapy.UDP:
            print("Client sends non-UDP packets")
            self.assertEquals(len(pkt_outs[0]), 0)
            return

        # UDPProxy should drop packets whose destination is not this proxy.
        if ip_orig.dst != curr_proxy_addr or l4_orig.dport != curr_proxy_port:
            print("Client sends packets that are not for the proxy")
            self.assertEquals(len(pkt_outs[0]), 0)
            return

        # UDPProxy should drop packets from clients that are not allowed.
        if not allow_client:
            print("Client is not allowed")
            self.assertEquals(len(pkt_outs[0]), 0)
            return

        self.assertEquals(len(pkt_outs[0]), 1)
        pkt_up = pkt_outs[0][0]

        # UDPProxy should send the UDP packet on behalf of s0.
        # |pkt_up|'s sport is randomly selected. We have to read it from pkt_up.
        l4_up = l4_orig.copy()
        l4_up.sport = pkt_up[scapy.UDP].sport
        l4_up.dport = next_proxy_port
        self.assertSamePackets(eth / ip_up / l4_up / l7, pkt_up)

        l4_reply = _swap_l4(l4_up)
        pkt_reply = eth / ip_reply / l4_reply / l7

        pkt_outs = self.run_module(module, 1, [pkt_reply], [0, 1, 2])
        self.assertEquals(len(pkt_outs[0]), 0)
        self.assertEquals(len(pkt_outs[1]), 1)
        self.assertEquals(len(pkt_outs[2]), 0)
        pkt_down = pkt_outs[1][0]

        l4_down = _swap_l4(l4_orig).copy()
        l4_down.sport = curr_proxy_port
        self.assertSamePackets(eth / ip_down / l4_down / l7, pkt_down)

    def test_invisv_udp_proxy_selfconfig(self):
        # Send initial conf unsorted, see that it comes back sorted
        # (note that this is a bit different from other modules
        # where argument order often matters).
        iconf = {'ext_addrs': [{'ext_addr': '192.168.1.1',
                                'port_ranges': [{'begin': 1, 'end': 1024},
                                                {'begin': 1025, 'end': 65535}]}]}
        proxy = INVISVUDPProxy(**iconf)
        arg = pb_conv.protobuf_to_dict(proxy.get_initial_arg())
        expect_config = {}
        cur_config = pb_conv.protobuf_to_dict(proxy.get_runtime_config())
        print("arg ", arg)
        print("iconf", iconf)
        print("cur_config", cur_config)
        print("expected_config", expect_config)
        assert arg == iconf and cur_config == expect_config

        curr_proxy = pb_conv.protobuf_to_dict(proxy.get_proxy())
        next_hop_proxy = pb_conv.protobuf_to_dict(proxy.get_next_hop_proxy())
        assert curr_proxy['proxy_addr'] == '0.0.0.0'
        assert next_hop_proxy['proxy_addr'] == '0.0.0.0'

        proxy.set_proxy(proxy_addr='127.0.0.1', proxy_port=1)
        proxy.set_next_hop_proxy(proxy_addr='192.168.0.1', proxy_port=2)
        curr_proxy = pb_conv.protobuf_to_dict(proxy.get_proxy())
        next_hop_proxy = pb_conv.protobuf_to_dict(proxy.get_next_hop_proxy())
        assert curr_proxy['proxy_addr'] == '127.0.0.1'
        assert curr_proxy['proxy_port'] == 1
        assert next_hop_proxy['proxy_addr'] == '192.168.0.1'
        assert next_hop_proxy['proxy_port'] == 2

    def test_invisv_udp_proxy_tcp_drop(self):
        proxy_config = [{'ext_addr': '127.0.0.1'}]
        proxy = INVISVUDPProxy(ext_addrs=proxy_config)
        proxy.set_proxy(proxy_addr='127.0.0.1', proxy_port=1)
        proxy.set_next_hop_proxy(proxy_addr='192.168.0.1', proxy_port=2)
        proxy.set_client(client_addr='172.16.0.2', client_port=56797, allow=True)
        self._test_l4(
            proxy,
            scapy.IP(src='172.16.0.2', dst='127.0.0.1'),
            scapy.TCP(sport=56797, dport=1),
            True,
            '127.0.0.1', 1, '192.168.0.1', 2)

    def test_invisv_udp_proxy_udp(self):
        proxy_config = [{'ext_addr': '127.0.0.1'}]
        proxy = INVISVUDPProxy(ext_addrs=proxy_config)
        proxy.set_proxy(proxy_addr='127.0.0.1', proxy_port=1)
        proxy.set_next_hop_proxy(proxy_addr='192.168.0.1', proxy_port=2)
        proxy.set_client(client_addr='172.16.0.2', client_port=56797, allow=True)
        self._test_l4(
            proxy,
            scapy.IP(src='172.16.0.2', dst='127.0.0.1'),
            scapy.UDP(sport=56797, dport=1),
            True,
            '127.0.0.1', 1, '192.168.0.1', 2)

    def test_invisv_udp_proxy_udp_with_zero_cksum(self):
        proxy_config = [{'ext_addr': '127.0.0.1'}]
        proxy = INVISVUDPProxy(ext_addrs=proxy_config)
        proxy.set_proxy(proxy_addr='127.0.0.1', proxy_port=1)
        proxy.set_next_hop_proxy(proxy_addr='192.168.0.1', proxy_port=2)
        proxy.set_client(client_addr='172.16.0.2', client_port=56797, allow=True)
        self._test_l4(
            proxy,
            scapy.IP(src='172.16.0.2', dst='127.0.0.1'),
            scapy.UDP(sport=56797, dport=1, chksum=0),
            True,
            '127.0.0.1', 1, '192.168.0.1', 2)

    def test_invisv_udp_proxy_udp_incorrect_dst_proxy(self):
        proxy_config = [{'ext_addr': '127.0.0.1'}]
        proxy = INVISVUDPProxy(ext_addrs=proxy_config)
        proxy.set_proxy(proxy_addr='127.0.0.1', proxy_port=1)
        proxy.set_next_hop_proxy(proxy_addr='192.168.0.1', proxy_port=2)
        proxy.set_client(client_addr='172.16.0.2', client_port=56797, allow=True)
        self._test_l4(
            proxy,
            scapy.IP(src='172.16.0.2', dst='127.0.0.2'),
            scapy.UDP(sport=56797, dport=1),
            True,
            '127.0.0.1', 1, '192.168.0.1', 2)
        self._test_l4(
            proxy,
            scapy.IP(src='172.16.0.2', dst='127.0.0.1'),
            scapy.UDP(sport=56797, dport=2, chksum=0),
            True,
            '127.0.0.1', 1, '192.168.0.1', 2)

    def test_invisv_udp_proxy_udp_client_not_allowed(self):
        proxy_config = [{'ext_addr': '127.0.0.1'}]
        proxy = INVISVUDPProxy(ext_addrs=proxy_config)
        proxy.set_proxy(proxy_addr='127.0.0.1', proxy_port=1)
        proxy.set_next_hop_proxy(proxy_addr='192.168.0.1', proxy_port=2)

        self._test_l4(
            proxy,
            scapy.IP(src='172.16.0.2', dst='127.0.0.1'),
            scapy.UDP(sport=56797, dport=1),
            False,
            '127.0.0.1', 1, '192.168.0.1', 2)

        proxy.set_client(client_addr='172.16.0.2', client_port=56797, allow=True)
        self._test_l4(
            proxy,
            scapy.IP(src='172.16.0.2', dst='127.0.0.1'),
            scapy.UDP(sport=56797, dport=1),
            True,
            '127.0.0.1', 1, '192.168.0.1', 2)

        proxy.set_client(client_addr='172.16.0.2', client_port=56797, allow=False)
        self._test_l4(
            proxy,
            scapy.IP(src='172.16.0.2', dst='127.0.0.1'),
            scapy.UDP(sport=56797, dport=1),
            False,
            '127.0.0.1', 1, '192.168.0.1', 2)
        
        proxy.set_client(client_addr='172.16.0.2', client_port=56797, allow=True)
        self._test_l4(
            proxy,
            scapy.IP(src='172.16.0.2', dst='127.0.0.1'),
            scapy.UDP(sport=56797, dport=1),
            True,
            '127.0.0.1', 1, '192.168.0.1', 2)
        
        # Allow a different client
        proxy.set_client(client_addr='172.16.0.3', client_port=50000, allow=True)
        self._test_l4(
            proxy,
            scapy.IP(src='172.16.0.3', dst='127.0.0.1'),
            scapy.UDP(sport=50000, dport=1),
            True,
            '127.0.0.1', 1, '192.168.0.1', 2)


suite = unittest.TestLoader().loadTestsFromTestCase(BessINVISVUDPProxyTest)
results = unittest.TextTestRunner(verbosity=2).run(suite)

if results.failures or results.errors:
    sys.exit(1)
