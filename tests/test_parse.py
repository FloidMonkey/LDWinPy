"""
Validacion offline del parser con paquetes CDP/LLDP sinteticos que imitan
lo que anuncian distintas marcas de switch. No requiere hardware ni captura.

Ejecutar:  python -m pytest tests/ -v      (o)     python tests/test_parse.py
"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scapy.all import Ether, Dot3, LLC, SNAP, wrpcap
from scapy.contrib import cdp, lldp

from ldwin.parse import parse_pcapng, parse_packet

CDP_MAC = "01:00:0c:cc:cc:cc"
LLDP_MAC = "01:80:c2:00:00:0e"


def _cdp_frame(src_mac, hdr_msg):
    """Encapsula CDP como en la realidad: 802.3 + LLC + SNAP (OUI Cisco, 0x2000)."""
    return (Dot3(src=src_mac, dst=CDP_MAC)
            / LLC(dsap=0xaa, ssap=0xaa, ctrl=3)
            / SNAP(OUI=0x00000c, code=0x2000)
            / hdr_msg)


# --------------------------------------------------------------------------- #
#  Constructores de paquetes por marca
# --------------------------------------------------------------------------- #
def cisco_cdp():
    """Cisco Catalyst hablando CDPv2."""
    hdr = cdp.CDPv2_HDR(vers=2, ttl=180)
    msg = (cdp.CDPMsgDeviceID(val=b"CORE-SW01.nagsa.local")
           / cdp.CDPMsgPortID(iface=b"GigabitEthernet0/24")
           / cdp.CDPMsgAddr(addr=[cdp.CDPAddrRecordIPv4(addr="10.0.0.1")])
           / cdp.CDPMsgPlatform(val=b"cisco WS-C2960X-48TS-L")
           / cdp.CDPMsgSoftwareVersion(val=b"Cisco IOS 15.2(2)E7")
           / cdp.CDPMsgNativeVLAN(vlan=100)
           / cdp.CDPMsgDuplex(duplex=1)
           / cdp.CDPMsgVTPMgmtDomain(val=b"NAGSA")
           / cdp.CDPMsgCapabilities(cap=0x28))  # Switch + IGMP
    return _cdp_frame("00:11:22:33:44:55", hdr / msg)


def mikrotik_cdp():
    """Mikrotik RouterOS tambien puede anunciar CDP."""
    hdr = cdp.CDPv2_HDR(vers=2, ttl=120)
    msg = (cdp.CDPMsgDeviceID(val=b"MikroTik-CRS326")
           / cdp.CDPMsgPortID(iface=b"sfp-sfpplus1")
           / cdp.CDPMsgAddr(addr=[cdp.CDPAddrRecordIPv4(addr="192.168.88.1")])
           / cdp.CDPMsgPlatform(val=b"MikroTik")
           / cdp.CDPMsgSoftwareVersion(val=b"RouterOS 7.11"))
    return _cdp_frame("dc:2c:6e:11:22:33", hdr / msg)


def _org_8021_pvid(pvid):
    return lldp.LLDPDUGenericOrganisationSpecific(
        org_code=0x0080C2, subtype=1, data=pvid.to_bytes(2, "big"))


def _org_8021_vlanname(vlan_id, name):
    nb = name.encode()
    data = vlan_id.to_bytes(2, "big") + bytes([len(nb)]) + nb
    return lldp.LLDPDUGenericOrganisationSpecific(
        org_code=0x0080C2, subtype=3, data=data)


def _org_8023_macphy(full_duplex=True):
    autoneg = 0x02 if full_duplex else 0x00
    return lldp.LLDPDUGenericOrganisationSpecific(
        org_code=0x00120F, subtype=1,
        data=bytes([autoneg]) + b"\x00\x00\x00\x00")


def tplink_omada_lldp():
    """TP-Link Omada (switch gestionado) hablando LLDP estandar."""
    du = (lldp.LLDPDUChassisID(subtype=4, id=b"\xac\x84\xc6\x01\x02\x03")
          / lldp.LLDPDUPortID(subtype=5, id=b"Port 8")
          / lldp.LLDPDUTimeToLive(ttl=120)
          / lldp.LLDPDUSystemName(system_name="Omada-SG3428")
          / lldp.LLDPDUSystemDescription(
              description="TP-Link JetStream 24-Port Gigabit L2+ Managed Switch TL-SG3428")
          / lldp.LLDPDUPortDescription(description="Copper-8")
          / lldp.LLDPDUManagementAddress(
              management_address_subtype=1, management_address=b"\xc0\xa8\x01\x0a",
              interface_numbering_subtype=2, interface_number=8)
          / lldp.LLDPDUSystemCapabilities(mac_bridge_available=1, mac_bridge_enabled=1,
                                          router_available=1)
          / _org_8021_pvid(200)
          / _org_8021_vlanname(200, "OFICINAS")
          / _org_8023_macphy(True)
          / lldp.LLDPDUEndOfLLDPDU())
    return Ether(src="ac:84:c6:01:02:03", dst=LLDP_MAC) / lldp.LLDPDU() / du


def dlink_lldp():
    """D-Link switch gestionado hablando LLDP."""
    du = (lldp.LLDPDUChassisID(subtype=4, id=b"\x00\x1b\x11\xaa\xbb\xcc")
          / lldp.LLDPDUPortID(subtype=5, id=b"1/0/12")
          / lldp.LLDPDUTimeToLive(ttl=120)
          / lldp.LLDPDUSystemName(system_name="DGS-1210-28")
          / lldp.LLDPDUSystemDescription(
              description="D-Link DGS-1210-28 Gigabit Smart Switch")
          / lldp.LLDPDUManagementAddress(
              management_address_subtype=1, management_address=b"\x0a\x0a\x0a\x02",
              interface_numbering_subtype=2, interface_number=12)
          / lldp.LLDPDUSystemCapabilities(mac_bridge_available=1, mac_bridge_enabled=1)
          / _org_8021_pvid(1)
          / lldp.LLDPDUEndOfLLDPDU())
    return Ether(src="00:1b:11:aa:bb:cc", dst=LLDP_MAC) / lldp.LLDPDU() / du


def mikrotik_lldp():
    """Mikrotik hablando LLDP (ademas de CDP)."""
    du = (lldp.LLDPDUChassisID(subtype=4, id=b"\xdc\x2c\x6e\x11\x22\x33")
          / lldp.LLDPDUPortID(subtype=5, id=b"ether5")
          / lldp.LLDPDUTimeToLive(ttl=120)
          / lldp.LLDPDUSystemName(system_name="MikroTik-hEX")
          / lldp.LLDPDUSystemDescription(
              description="RouterOS RB750Gr3 7.11")
          / lldp.LLDPDUManagementAddress(
              management_address_subtype=1, management_address=b"\xc0\xa8\x58\x01",
              interface_numbering_subtype=2, interface_number=5)
          / lldp.LLDPDUSystemCapabilities(router_available=1, router_enabled=1,
                                          mac_bridge_available=1)
          / _org_8021_pvid(1)
          / lldp.LLDPDUEndOfLLDPDU())
    return Ether(src="dc:2c:6e:11:22:33", dst=LLDP_MAC) / lldp.LLDPDU() / du


# --------------------------------------------------------------------------- #
#  Tests
# --------------------------------------------------------------------------- #
def _roundtrip(packets):
    """Escribe a pcapng (como haria pktmon) y re-parsea desde disco."""
    tmp = os.path.join(tempfile.gettempdir(), "ldwin_test.pcapng")
    wrpcap(tmp, packets)
    return {n.switch_name: n for n in parse_pcapng(tmp)}


def test_all_brands():
    pkts = [cisco_cdp(), mikrotik_cdp(), tplink_omada_lldp(),
            dlink_lldp(), mikrotik_lldp()]
    res = _roundtrip(pkts)

    # Cisco CDP
    c = res["CORE-SW01.nagsa.local"]
    assert c.protocol == "CDP"
    assert c.port_id == "GigabitEthernet0/24"
    assert c.switch_ip == "10.0.0.1"
    assert "WS-C2960X" in c.switch_model
    assert c.vlan == "100"
    assert c.duplex == "Full"
    assert c.vtp_domain == "NAGSA"
    assert "Switch" in c.capabilities

    # Mikrotik CDP
    m = res["MikroTik-CRS326"]
    assert m.switch_ip == "192.168.88.1"
    assert m.port_id == "sfp-sfpplus1"
    assert "RouterOS" in m.switch_version

    # TP-Link Omada LLDP
    t = res["Omada-SG3428"]
    assert t.protocol == "LLDP"
    assert t.port_id == "Port 8"
    assert t.switch_ip == "192.168.1.10"
    assert t.vlan == "200"
    assert t.vlan_name == "OFICINAS"
    assert t.duplex == "Full"
    assert "TL-SG3428" in t.switch_desc
    assert "Bridge" in t.capabilities

    # D-Link LLDP
    d = res["DGS-1210-28"]
    assert d.protocol == "LLDP"
    assert d.port_id == "1/0/12"
    assert d.switch_ip == "10.10.10.2"
    assert "DGS-1210-28" in d.switch_desc

    # Mikrotik LLDP
    ml = res["MikroTik-hEX"]
    assert ml.port_id == "ether5"
    assert ml.switch_ip == "192.168.88.1"
    assert "Router" in ml.capabilities

    print("OK - %d vecinos parseados correctamente:" % len(res))
    for name, n in res.items():
        print(f"  [{n.protocol:4}] {name:24} port={n.port_id:22} "
              f"ip={n.switch_ip:15} vlan={n.vlan}")


if __name__ == "__main__":
    test_all_brands()
    print("\nTodos los tests pasaron.")
