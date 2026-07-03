"""
Parseo normalizado de vecinos CDP / LLDP.

Toma un archivo .pcapng (capturado con pktmon) o paquetes scapy y devuelve
una lista de objetos NeighborInfo con un conjunto de campos unificado, sin
importar la marca del switch (Cisco, Mikrotik, TP-Link Omada, D-Link, ...).

CDP es propietario de Cisco (y lo habla Mikrotik). LLDP es el estandar abierto
que hablan practicamente todas las marcas, por eso es el corazon del multimarca.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Optional, List, Dict, Any

from scapy.all import Ether, Dot3
from scapy.contrib import cdp, lldp


# --- IEEE OUIs usados en los TLV "Organisation Specific" de LLDP ---
OUI_8021 = 0x0080C2  # IEEE 802.1  (VLAN, PVID, VLAN name)
OUI_8023 = 0x00120F  # IEEE 802.3  (MAC/PHY = duplex/autoneg, Power via MDI)
OUI_MED = 0x0012BB   # TIA LLDP-MED (VLAN de voz, PoE extendido, inventario)

_MED_DEVTYPE = {
    1: "Endpoint Clase I (generico)", 2: "Endpoint Clase II (media)",
    3: "Endpoint Clase III (telefono)", 4: "Conectividad de red (switch/AP)",
}
_MED_APP = {
    1: "voz", 2: "senalizacion_voz", 3: "voz_invitada",
    4: "senalizacion_voz_invitada", 5: "video_vigilancia",
    6: "senalizacion_video", 7: "videoconferencia", 8: "streaming_video",
}
_MED_INVENTORY = {
    5: "hw_revision", 6: "fw_revision", 7: "sw_revision",
    8: "serial", 9: "fabricante", 10: "modelo", 11: "asset_id",
}


@dataclass
class NeighborInfo:
    """Informacion normalizada de un dispositivo vecino descubierto."""
    protocol: str = ""                 # "CDP" o "LLDP"
    src_mac: str = ""                  # MAC origen del frame (el switch)
    dst_mac: str = ""                  # MAC destino (multicast del protocolo)

    switch_name: str = ""              # nombre / device-id / system-name
    switch_ip: str = ""                # direccion de gestion
    switch_model: str = ""             # plataforma / modelo
    switch_desc: str = ""              # descripcion de sistema (OS/firmware)
    switch_version: str = ""           # version de software / IOS / firmware

    port_id: str = ""                  # puerto remoto (id)
    port_desc: str = ""                # descripcion del puerto remoto
    vlan: str = ""                     # native VLAN (CDP) / PVID (LLDP)
    vlan_name: str = ""                # nombre de la VLAN (si viene)
    duplex: str = ""                   # Half / Full
    capabilities: str = ""             # Router, Bridge, WLAN AP, ...
    vtp_domain: str = ""               # dominio VTP (solo CDP)
    mgmt_vlan: str = ""                # VLAN de gestion (si viene)
    ttl: str = ""                      # time-to-live anunciado
    power: str = ""                    # PoE (mW / clase) si viene

    raw: Dict[str, Any] = field(default_factory=dict)  # todo lo crudo extra

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def is_empty(self) -> bool:
        return not (self.switch_name or self.switch_ip or self.port_id
                    or self.switch_model)


# --------------------------------------------------------------------------- #
#  Utilidades
# --------------------------------------------------------------------------- #
def _txt(v) -> str:
    """Decodifica bytes/valores a texto imprimible y limpio."""
    if v is None:
        return ""
    if isinstance(v, bytes):
        try:
            v = v.decode("utf-8", "replace")
        except Exception:
            v = v.decode("latin-1", "replace")
    return str(v).strip().replace("\x00", "")


def _mac(b) -> str:
    if isinstance(b, bytes):
        return ":".join(f"{x:02x}" for x in b)
    return _txt(b)


def _iter_layers(pkt):
    """Itera todas las capas de un paquete scapy."""
    layer = pkt
    while layer:
        yield layer
        layer = layer.payload if layer.payload else None


def _l2_macs(pkt):
    """Devuelve (src, dst) del frame, sea Ethernet II (Ether) o 802.3 (Dot3)."""
    for cls in (Ether, Dot3):
        if pkt.haslayer(cls):
            return _mac(pkt[cls].src), _mac(pkt[cls].dst)
    return "", ""


# --------------------------------------------------------------------------- #
#  CDP
# --------------------------------------------------------------------------- #
def _parse_cdp(pkt) -> Optional[NeighborInfo]:
    if not pkt.haslayer(cdp.CDPv2_HDR):
        return None
    n = NeighborInfo(protocol="CDP")
    n.src_mac, n.dst_mac = _l2_macs(pkt)
    hdr = pkt[cdp.CDPv2_HDR]
    n.ttl = _txt(hdr.ttl)

    # Tras re-disecar desde pcap, los TLV quedan en hdr.msg (lista).
    # Al construir en memoria con "/" quedan como capas de payload.
    msgs = list(hdr.msg) if getattr(hdr, "msg", None) else list(_iter_layers(hdr))
    for l in msgs:
        if isinstance(l, cdp.CDPMsgDeviceID):
            n.switch_name = _txt(l.val)
        elif isinstance(l, cdp.CDPMsgPortID):
            n.port_id = _txt(l.iface)
        elif isinstance(l, cdp.CDPMsgPlatform):
            n.switch_model = _txt(l.val)
        elif isinstance(l, cdp.CDPMsgSoftwareVersion):
            n.switch_version = _txt(l.val)
            n.switch_desc = _txt(l.val)
        elif isinstance(l, cdp.CDPMsgNativeVLAN):
            n.vlan = _txt(l.vlan)
        elif isinstance(l, cdp.CDPMsgDuplex):
            n.duplex = {0: "Half", 1: "Full"}.get(int(l.duplex), _txt(l.duplex))
        elif isinstance(l, cdp.CDPMsgVTPMgmtDomain):
            n.vtp_domain = _txt(l.val)
        elif isinstance(l, (cdp.CDPMsgAddr, cdp.CDPMsgMgmtAddr)):
            ip = _cdp_first_addr(l)
            if ip and not n.switch_ip:
                n.switch_ip = ip
        elif isinstance(l, cdp.CDPMsgCapabilities):
            n.capabilities = _cdp_caps(int(l.cap))
        elif isinstance(l, (cdp.CDPMsgPower, cdp.CDPMsgPowerRequest,
                            cdp.CDPMsgPowerAvailable)):
            n.raw.setdefault("power_tlv", _txt(l.summary()))
    return n


def _cdp_first_addr(layer) -> str:
    try:
        for rec in layer.addr:
            a = getattr(rec, "addr", None)
            if a:
                return _txt(a)
    except Exception:
        pass
    return ""


def _cdp_caps(cap: int) -> str:
    bits = [
        (0x01, "Router"), (0x02, "Transparent Bridge"),
        (0x04, "Source Route Bridge"), (0x08, "Switch"),
        (0x10, "Host"), (0x20, "IGMP"), (0x40, "Repeater"),
    ]
    return ", ".join(name for mask, name in bits if cap & mask)


# --------------------------------------------------------------------------- #
#  LLDP
# --------------------------------------------------------------------------- #
def _parse_lldp(pkt) -> Optional[NeighborInfo]:
    if not pkt.haslayer(lldp.LLDPDU):
        return None
    n = NeighborInfo(protocol="LLDP")
    n.src_mac, n.dst_mac = _l2_macs(pkt)

    for l in _iter_layers(pkt):
        if isinstance(l, lldp.LLDPDUSystemName):
            n.switch_name = _txt(l.system_name)
        elif isinstance(l, lldp.LLDPDUSystemDescription):
            n.switch_desc = _txt(l.description)
            if not n.switch_version:
                n.switch_version = _txt(l.description)
        elif isinstance(l, lldp.LLDPDUPortID):
            n.port_id = _lldp_id(l)
        elif isinstance(l, lldp.LLDPDUPortDescription):
            n.port_desc = _txt(l.description)
        elif isinstance(l, lldp.LLDPDUChassisID):
            n.raw["chassis_id"] = _lldp_id(l)
        elif isinstance(l, lldp.LLDPDUManagementAddress):
            ip = _lldp_mgmt_addr(l)
            if ip and not n.switch_ip:
                n.switch_ip = ip
        elif isinstance(l, lldp.LLDPDUSystemCapabilities):
            n.capabilities = _lldp_caps(l)
        elif isinstance(l, lldp.LLDPDUTimeToLive):
            n.ttl = _txt(getattr(l, "ttl", ""))
        elif isinstance(l, lldp.LLDPDUGenericOrganisationSpecific):
            _lldp_org(l, n)

    # Muchos switches ponen el modelo en la descripcion del sistema.
    if not n.switch_model and n.switch_desc:
        n.switch_model = n.switch_desc.split("\n")[0][:80]
    # Si no vino system-name, usar el chassis id como identificador.
    if not n.switch_name and n.raw.get("chassis_id"):
        n.switch_name = n.raw["chassis_id"]
    return n


def _lldp_id(layer) -> str:
    """Formatea Chassis/Port ID segun su subtipo (MAC vs texto)."""
    val = getattr(layer, "id", b"")
    subtype = int(getattr(layer, "subtype", 0) or 0)
    # subtipos que son direcciones MAC: Chassis(4) MAC, Port(3) MAC
    if isinstance(val, bytes) and subtype in (3, 4) and len(val) == 6:
        return _mac(val)
    return _txt(val)


def _lldp_mgmt_addr(layer) -> str:
    subtype = int(getattr(layer, "management_address_subtype", 0) or 0)
    addr = getattr(layer, "management_address", b"")
    if isinstance(addr, bytes):
        if subtype == 1 and len(addr) == 4:            # IPv4
            return ".".join(str(x) for x in addr)
        if subtype == 2 and len(addr) == 16:           # IPv6
            return ":".join(f"{addr[i]:02x}{addr[i+1]:02x}"
                             for i in range(0, 16, 2))
    return _txt(addr)


def _lldp_caps(layer) -> str:
    names = [
        ("router", "Router"), ("mac_bridge", "Bridge"),
        ("wlan_access_point", "WLAN AP"), ("telephone", "Telephone"),
        ("repeater", "Repeater"), ("station_only", "Station"),
        ("docsis_cable_device", "DOCSIS"),
        ("c_vlan_component", "C-VLAN"), ("s_vlan_component", "S-VLAN"),
    ]
    out = []
    for attr, label in names:
        if int(getattr(layer, f"{attr}_available", 0) or 0):
            enabled = int(getattr(layer, f"{attr}_enabled", 0) or 0)
            out.append(label + ("*" if enabled else ""))
    return ", ".join(out)


def _lldp_org(layer, n: NeighborInfo) -> None:
    """Decodifica TLVs organizacionales 802.1 (VLAN) y 802.3 (duplex/PoE)."""
    org = int(getattr(layer, "org_code", 0) or 0)
    subtype = int(getattr(layer, "subtype", 0) or 0)
    data = getattr(layer, "data", b"") or b""

    if org == OUI_8021:
        if subtype == 1 and len(data) >= 2:            # Port VLAN ID (PVID)
            n.vlan = str(int.from_bytes(data[:2], "big"))
        elif subtype == 3 and len(data) >= 4:          # VLAN Name
            vlan_id = int.from_bytes(data[:2], "big")
            name_len = data[2]
            name = _txt(data[3:3 + name_len])
            if name:
                n.vlan_name = name
            if not n.vlan and vlan_id:
                n.vlan = str(vlan_id)
    elif org == OUI_8023:
        if subtype == 1 and len(data) >= 1:            # MAC/PHY config/status
            # bit1 (0x02) del primer byte = duplex actual (1=full)
            autoneg_status = data[0]
            n.raw["mac_phy"] = data.hex()
            if len(data) >= 1:
                n.duplex = "Full" if (autoneg_status & 0x02) else "Half"
        elif subtype == 2:                             # Power via MDI
            n.raw["power_mdi"] = data.hex()
            if not n.power:
                # byte2 = power class (1..5 => Clase 0..4) si esta presente
                if len(data) >= 3 and 1 <= data[2] <= 5:
                    n.power = f"PoE clase {data[2] - 1}"
                else:
                    n.power = "PoE anunciado"
    elif org == OUI_MED:
        _lldp_med(subtype, data, n)
    else:
        n.raw.setdefault("org_%06x_%d" % (org, subtype), data.hex())


def _lldp_med(subtype: int, data: bytes, n: NeighborInfo) -> None:
    """TIA LLDP-MED: capacidades, politica de red (VLAN voz), PoE, inventario."""
    if subtype == 1 and len(data) >= 3:                # MED capabilities
        n.raw["lldp_med"] = _MED_DEVTYPE.get(data[2], f"tipo {data[2]}")
    elif subtype == 2 and len(data) >= 4:              # Network Policy
        app = data[0]
        val = int.from_bytes(data[1:4], "big")
        # bits: U(23) T(22) X(21) VLAN(20..9) L2prio(8..6) DSCP(5..0)
        vlan = (val >> 9) & 0xFFF
        tagged = (val >> 22) & 1
        name = _MED_APP.get(app, f"app{app}")
        n.raw[f"med_{name}"] = (f"VLAN {vlan}" + (" (tagged)" if tagged else "")
                                if vlan else "sin VLAN")
        if app == 1 and vlan:
            n.raw["voice_vlan"] = str(vlan)
    elif subtype == 4 and len(data) >= 3:              # Extended Power via MDI
        watts = int.from_bytes(data[1:3], "big") / 10.0
        if watts:
            n.power = f"{watts:g} W (PoE)"
    elif subtype in _MED_INVENTORY:                    # Inventario (serial, etc.)
        val = _txt(data)
        if val:
            n.raw[_MED_INVENTORY[subtype]] = val


# --------------------------------------------------------------------------- #
#  API publica
# --------------------------------------------------------------------------- #
def parse_packet(pkt) -> Optional[NeighborInfo]:
    """Devuelve NeighborInfo si el paquete es CDP o LLDP, si no None."""
    if pkt.haslayer(lldp.LLDPDU):
        info = _parse_lldp(pkt)
    elif pkt.haslayer(cdp.CDPv2_HDR):
        info = _parse_cdp(pkt)
    else:
        return None
    if info and not info.is_empty():
        return info
    return None


def parse_pcapng(path: str) -> List[NeighborInfo]:
    """Lee un pcapng y devuelve la lista de vecinos descubiertos (sin duplicar)."""
    from scapy.all import rdpcap

    packets = rdpcap(path)
    seen: Dict[tuple, NeighborInfo] = {}
    for pkt in packets:
        info = parse_packet(pkt)
        if not info:
            continue
        key = (info.protocol, info.switch_name, info.port_id, info.src_mac)
        seen[key] = info  # el mas reciente gana
    return list(seen.values())
