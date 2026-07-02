"""
Diagnostico de enlace: ¿switch administrable, NO administrable o enlace directo?

Un switch no administrable no emite CDP/LLDP, asi que no puede anunciarse.
Pero SI se puede inferir su presencia observando el segmento:

  1. Enlace fisico activo (Get-NetAdapter) + NADIE anuncia CDP/LLDP + llega
     trafico broadcast (ARP) de varios equipos distintos
        -> tipico de switch NO administrable (o administrable con LLDP apagado).
  2. Se reciben anuncios CDP/LLDP de DOS o mas equipos distintos por el mismo
     puerto -> hay un dispositivo intermedio (switch no administrable / hub)
     reenviando anuncios de varios origenes hacia tu PC. Un switch
     administrable solo enviaria el suyo (LLDP usa una MAC reservada 802.1D
     que los bridges compatibles NO reenvian).
  3. Enlace activo, sin anuncios y sin trafico de terceros -> enlace directo
     a otro equipo o segmento vacio.

Para que la atribucion sea correcta conviene diagnosticar UNA NIC concreta.
"""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from .parse import NeighborInfo, parse_packet, _l2_macs


@dataclass
class LinkDiag:
    nic_name: str = ""
    link_status: str = ""
    link_speed: str = ""
    neighbors: List[NeighborInfo] = field(default_factory=list)
    announcer_macs: Set[str] = field(default_factory=set)
    other_macs: Dict[str, int] = field(default_factory=dict)  # mac -> frames
    verdict: str = ""
    details: List[str] = field(default_factory=list)

    def report(self) -> str:
        from . import export
        lines = ["=" * 62, "  DIAGNOSTICO DE ENLACE", "=" * 62]
        if self.nic_name:
            estado = self.link_status or "?"
            vel = f" @ {self.link_speed}" if self.link_speed else ""
            lines.append(f"  NIC: {self.nic_name}  (enlace: {estado}{vel})")
        lines.append(f"  Anuncios CDP/LLDP: {len(self.neighbors)} "
                     f"(de {len(self.announcer_macs)} equipo(s) distintos)")
        lines.append(f"  Otros dispositivos vistos por broadcast/ARP: "
                     f"{len(self.other_macs)}")
        for mac, cnt in sorted(self.other_macs.items(),
                               key=lambda kv: -kv[1])[:10]:
            lines.append(f"      {mac}  ({cnt} tramas)")
        lines.append("-" * 62)
        lines.append(f"  VEREDICTO: {self.verdict}")
        for d in self.details:
            lines.append(f"    - {d}")
        lines.append("=" * 62)
        out = "\n".join(lines) + "\n"
        if self.neighbors:
            out += "\n" + export.to_text(self.neighbors)
        return out


# --------------------------------------------------------------------------- #
#  Estado fisico del enlace (Get-NetAdapter)
# --------------------------------------------------------------------------- #
def get_link_state(nic_name: str) -> Tuple[str, str]:
    """Devuelve (status, linkspeed) de la NIC via PowerShell; ("","") si falla."""
    ps = ("Get-NetAdapter | Select-Object Name,Status,LinkSpeed,MacAddress "
          "| ConvertTo-Json")
    try:
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
            capture_output=True, text=True, timeout=30,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        data = json.loads(proc.stdout or "[]")
        if isinstance(data, dict):
            data = [data]
        for a in data:
            if str(a.get("Name", "")).lower() == nic_name.lower():
                return str(a.get("Status", "")), str(a.get("LinkSpeed", ""))
    except Exception:
        pass
    return "", ""


# --------------------------------------------------------------------------- #
#  Analisis del pcapng
# --------------------------------------------------------------------------- #
def analyze_pcap(pcapng: str, own_macs: Set[str]
                 ) -> Tuple[List[NeighborInfo], Set[str], Dict[str, int]]:
    """
    Separa el trafico capturado en:
      - vecinos CDP/LLDP (deduplicados),
      - MACs que anunciaron CDP/LLDP,
      - MACs de terceros vistas en el resto del trafico (ARP/broadcast).
    """
    from scapy.all import rdpcap

    packets = rdpcap(pcapng)
    neighbors: Dict[tuple, NeighborInfo] = {}
    announcers: Set[str] = set()
    others: Dict[str, int] = {}

    for pkt in packets:
        src, _dst = _l2_macs(pkt)
        src = (src or "").lower()
        info = parse_packet(pkt)
        if info:
            key = (info.protocol, info.switch_name, info.port_id, info.src_mac)
            neighbors[key] = info
            if src:
                announcers.add(src)
        elif src and src not in own_macs:
            others[src] = others.get(src, 0) + 1

    # Las MACs que anuncian no cuentan como "terceros"
    for mac in announcers:
        others.pop(mac, None)
    return list(neighbors.values()), announcers, others


def build_verdict(link_status: str, neighbors: List[NeighborInfo],
                  announcers: Set[str], others: Dict[str, int]
                  ) -> Tuple[str, List[str]]:
    n, a, o = len(neighbors), len(announcers), len(others)
    link_down = link_status.lower() in ("down", "disconnected", "disabled")

    if n and a >= 2:
        return ("SWITCH ADMINISTRABLE DETECTADO, PERO CON DISPOSITIVO "
                "INTERMEDIO (probable switch NO administrable o hub)", [
            f"Se recibieron anuncios de {a} equipos DISTINTOS por el mismo "
            "segmento.",
            "Un switch administrable solo enviaria su propio anuncio "
            "(la MAC LLDP es reservada y los bridges compatibles no la "
            "reenvian).",
            "Que lleguen varios anuncios indica que algo intermedio los esta "
            "reenviando: tipicamente un switch no administrable o un hub.",
        ])
    if n:
        det = [f"Anuncio recibido de: {neighbors[0].switch_name} "
               f"(puerto {neighbors[0].port_id})."]
        if o >= 1:
            det.append(f"Ademas se ve trafico broadcast de {o} equipo(s), "
                       "normal en un segmento conmutado.")
        det.append("Nota: un switch no administrable intermedio que reenvie "
                   "el LLDP de UN solo origen no es detectable por este "
                   "metodo.")
        return ("CONECTADO A SWITCH ADMINISTRABLE", det)

    # --- sin anuncios CDP/LLDP ---
    if link_down:
        return ("ENLACE CAIDO", [
            "La NIC reporta el enlace abajo. Revisa cable/puerto antes de "
            "diagnosticar."])
    if o >= 3:
        return ("SWITCH NO ADMINISTRABLE (probable)", [
            f"El enlace esta activo y llega trafico de {o} equipos distintos, "
            "pero NINGUNO anuncia CDP/LLDP.",
            "Un switch administrable normalmente anunciaria LLDP; que haya "
            "varios equipos y silencio de descubrimiento apunta a un switch "
            "no administrable.",
            "Alternativa: switch administrable con CDP/LLDP deshabilitado.",
        ])
    if o >= 1:
        return ("POSIBLE SWITCH NO ADMINISTRABLE O ENLACE DIRECTO", [
            f"Enlace activo con trafico de {o} equipo(s) pero sin anuncios "
            "CDP/LLDP.",
            "Con tan pocos emisores no se puede distinguir entre un enlace "
            "directo a otro equipo y un switch no administrable con poco "
            "trafico. Prueba con mas duracion (-t 120).",
        ])
    return ("SIN TRAFICO DE TERCEROS", [
        "Enlace activo pero no se capturo trafico de otros equipos.",
        "Puede ser un enlace directo a un dispositivo silencioso o un "
        "segmento vacio. Prueba con mas duracion.",
    ])


# --------------------------------------------------------------------------- #
#  Orquestacion
# --------------------------------------------------------------------------- #
def run_diagnosis(nic=None, duration: int = 45, on_status=None,
                  poll=None, workdir: Optional[str] = None) -> LinkDiag:
    """Captura (CDP/LLDP + ARP/broadcast) y emite un diagnostico del enlace."""
    from .capture import Capturer
    from .nics import list_nics

    own = {x.mac.lower() for x in list_nics(include_pktmon=False) if x.mac}
    comp = nic.pktmon_id if (nic and nic.pktmon_id) else "nics"
    workdir = workdir or os.path.join(tempfile.gettempdir(), "ldwinpy")

    cap = Capturer(workdir, comp=comp, on_status=on_status,
                   include_broadcast=True)
    pcapng = cap.capture(duration=duration, poll=poll)

    d = LinkDiag(nic_name=nic.name if nic else "(todas)")
    if nic:
        d.link_status, d.link_speed = get_link_state(nic.name)
    d.neighbors, d.announcer_macs, d.other_macs = analyze_pcap(pcapng, own)
    d.verdict, d.details = build_verdict(
        d.link_status, d.neighbors, d.announcer_macs, d.other_macs)
    return d
