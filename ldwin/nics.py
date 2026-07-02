"""
Enumeracion de tarjetas de red (NICs) en Windows.

Combina la lista de scapy (nombre, descripcion, MAC, IPs) con los componentes
de pktmon (para saber sobre que Id capturar). No requiere WMI ni dependencias
extra: scapy ya provee get_windows_if_list().
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class Nic:
    name: str = ""
    description: str = ""
    mac: str = ""
    ips: List[str] = field(default_factory=list)
    guid: str = ""
    index: Optional[int] = None
    pktmon_id: Optional[str] = None   # Id de componente pktmon (si se pudo mapear)

    @property
    def ipv4(self) -> str:
        for ip in self.ips:
            if ":" not in ip and not ip.startswith("169.254."):
                return ip
        return next((ip for ip in self.ips if ":" not in ip), "")

    def label(self) -> str:
        ip = self.ipv4 or "sin IPv4"
        return f"{self.name}  [{self.description}]  {self.mac}  {ip}"


def list_nics(include_pktmon: bool = True) -> List[Nic]:
    """Devuelve las NICs fisicas/relevantes con IPv4 o MAC valida."""
    from scapy.arch.windows import get_windows_if_list

    nics: List[Nic] = []
    for i in get_windows_if_list():
        mac = (i.get("mac") or "").strip()
        if not mac or mac == "00:00:00:00:00:00":
            continue
        nics.append(Nic(
            name=i.get("name", ""),
            description=i.get("description", ""),
            mac=mac,
            ips=list(i.get("ips", []) or []),
            guid=i.get("guid", ""),
            index=i.get("index"),
        ))

    if include_pktmon:
        _map_pktmon_ids(nics)
    return nics


def _map_pktmon_ids(nics: List[Nic]) -> None:
    """Asocia cada NIC con su Id de componente pktmon usando la MAC."""
    try:
        from .capture import list_nic_components
        comps = list_nic_components()
    except Exception:
        return
    by_mac = {}
    for c in comps:
        mac = (c.get("mac") or "").replace("-", ":").lower()
        if mac:
            by_mac[mac] = c["id"]
    for n in nics:
        cid = by_mac.get(n.mac.lower())
        if cid:
            n.pktmon_id = cid
