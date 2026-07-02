"""
Validacion offline del diagnostico de enlace (switch no administrable, etc.)
y de la decodificacion LLDP-MED (VLAN de voz, PoE en vatios).

Ejecutar:  python tests/test_diag.py
"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scapy.all import Ether, ARP, wrpcap
from scapy.contrib import lldp

from ldwin.diag import analyze_pcap, build_verdict
from ldwin.parse import parse_packet
from test_parse import tplink_omada_lldp, mikrotik_lldp, _cdp_frame

OWN_MAC = "aa:bb:cc:00:00:01"
BCAST = "ff:ff:ff:ff:ff:ff"


def _arp(src_mac, src_ip, target_ip):
    return (Ether(src=src_mac, dst=BCAST)
            / ARP(op=1, hwsrc=src_mac, psrc=src_ip, pdst=target_ip))


def _analyze(packets):
    tmp = os.path.join(tempfile.gettempdir(), "ldwin_diag_test.pcapng")
    wrpcap(tmp, packets)
    return analyze_pcap(tmp, {OWN_MAC})


def test_unmanaged_switch():
    """Trafico de varios equipos, cero anuncios -> switch NO administrable."""
    pkts = [_arp(f"00:00:5e:00:01:0{i}", f"10.0.0.{i}", "10.0.0.254")
            for i in range(1, 6)]
    pkts.append(_arp(OWN_MAC, "10.0.0.100", "10.0.0.254"))  # propio: se excluye
    neighbors, announcers, others = _analyze(pkts)
    assert len(neighbors) == 0
    assert len(others) == 5, f"esperaba 5 terceros, hubo {len(others)}"
    verdict, details = build_verdict("Up", neighbors, announcers, others)
    assert "NO ADMINISTRABLE" in verdict
    print(f"OK no-administrable: {verdict}")


def test_intermediate_device():
    """Anuncios de 2 equipos por el mismo segmento -> dispositivo intermedio."""
    pkts = [tplink_omada_lldp(), mikrotik_lldp(),
            _arp("00:00:5e:00:01:99", "10.0.0.99", "10.0.0.254")]
    neighbors, announcers, others = _analyze(pkts)
    assert len(neighbors) == 2
    assert len(announcers) == 2
    verdict, details = build_verdict("Up", neighbors, announcers, others)
    assert "INTERMEDIO" in verdict
    print(f"OK intermedio: {verdict}")


def test_managed_normal():
    """Un solo anunciante -> switch administrable normal."""
    pkts = [tplink_omada_lldp(),
            _arp("00:00:5e:00:01:07", "10.0.0.7", "10.0.0.254")]
    neighbors, announcers, others = _analyze(pkts)
    verdict, details = build_verdict("Up", neighbors, announcers, others)
    assert verdict == "CONECTADO A SWITCH ADMINISTRABLE"
    print(f"OK administrable: {verdict}")


def test_direct_or_quiet():
    """Enlace activo sin nada -> sin trafico de terceros."""
    neighbors, announcers, others = _analyze(
        [_arp(OWN_MAC, "10.0.0.100", "10.0.0.254")])
    verdict, _ = build_verdict("Up", neighbors, announcers, others)
    assert "SIN TRAFICO" in verdict
    verdict_down, _ = build_verdict("Down", [], set(), {})
    assert "CAIDO" in verdict_down
    print(f"OK directo/silencioso: {verdict} | {verdict_down}")


def test_lldp_med():
    """Decodificacion LLDP-MED: capacidades, VLAN de voz y PoE en vatios."""
    def med(subtype, data):
        return lldp.LLDPDUGenericOrganisationSpecific(
            org_code=0x0012BB, subtype=subtype, data=data)

    # Network Policy: app=1 (voz), tagged=1, VLAN=150, prio=5, dscp=46
    val = (1 << 22) | (150 << 9) | (5 << 6) | 46
    policy = bytes([1]) + val.to_bytes(3, "big")
    # Extended Power: byte flags + 65 (= 6.5 W en unidades de 0.1 W)
    power = bytes([0x51]) + (65).to_bytes(2, "big")
    # Capabilities: cap=0x0009, device type=4 (conectividad de red)
    caps = (0x0009).to_bytes(2, "big") + bytes([4])

    du = (lldp.LLDPDUChassisID(subtype=4, id=b"\x6c\x4c\xbc\xc9\xf2\xcb")
          / lldp.LLDPDUPortID(subtype=5, id=b"gi1/0/33")
          / lldp.LLDPDUTimeToLive(ttl=120)
          / lldp.LLDPDUSystemName(system_name="SG3452")
          / med(1, caps) / med(2, policy) / med(4, power)
          / med(8, b"SN123456789")
          / lldp.LLDPDUEndOfLLDPDU())
    pkt = (Ether(src="6c:4c:bc:c9:f2:cb", dst="01:80:c2:00:00:0e")
           / lldp.LLDPDU() / du)

    tmp = os.path.join(tempfile.gettempdir(), "ldwin_med_test.pcapng")
    wrpcap(tmp, [pkt])
    from scapy.all import rdpcap
    n = parse_packet(rdpcap(tmp)[0])
    assert n is not None
    assert n.raw.get("voice_vlan") == "150", n.raw
    assert "150" in n.raw.get("med_voz", "") and "tagged" in n.raw["med_voz"]
    assert n.power == "6.5 W (PoE)", n.power
    assert "Conectividad de red" in n.raw.get("lldp_med", "")
    assert n.raw.get("serial") == "SN123456789"
    print(f"OK LLDP-MED: voz VLAN {n.raw['voice_vlan']}, {n.power}, "
          f"serial {n.raw['serial']}")


if __name__ == "__main__":
    test_unmanaged_switch()
    test_intermediate_device()
    test_managed_normal()
    test_direct_or_quiet()
    test_lldp_med()
    print("\nTodos los tests de diagnostico pasaron.")
