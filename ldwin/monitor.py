"""
Modo monitoreo continuo: vigila los anuncios CDP/LLDP en ciclos consecutivos
y avisa cuando algo cambia respecto al estado conocido.

Eventos emitidos:
  BASELINE    primer ciclo: estado inicial de cada vecino descubierto
  CAMBIO      un vecino ya conocido cambio puerto / VLAN / IP / nombre / etc.
  NUEVO       aparecio un vecino que no estaba en el baseline
  PERDIDO     un vecino dejo de anunciarse durante N ciclos seguidos
  RECUPERADO  un vecino perdido volvio a anunciarse

La identidad de un vecino es su chassis-id (LLDP) o nombre (CDP), NO la MAC
origen del frame: al cambiarte de puerto muchos switches usan la MAC del
puerto nuevo, pero el chassis-id se mantiene — asi el evento se reporta como
CAMBIO de puerto del mismo switch y no como un switch distinto.
"""
from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, Dict, List, Optional, Set, Tuple

from .parse import NeighborInfo

# Campos vigilados y su etiqueta para el reporte de diffs
_WATCH = {
    "switch_name": "Nombre del switch",
    "port_id": "Puerto",
    "port_desc": "Descripcion del puerto",
    "vlan": "VLAN",
    "vlan_name": "Nombre VLAN",
    "switch_ip": "IP del switch",
    "duplex": "Duplex",
    "power": "PoE",
}


def _key(n: NeighborInfo) -> Tuple[str, str]:
    """Identidad estable de un vecino (sobrevive a cambios de puerto)."""
    return (n.protocol,
            n.raw.get("chassis_id") or n.switch_name or n.src_mac)


@dataclass
class MonitorEvent:
    time: str
    kind: str                      # BASELINE|CAMBIO|NUEVO|PERDIDO|RECUPERADO
    who: str                       # identificador legible del vecino
    message: str
    diffs: Dict[str, Tuple[str, str]] = field(default_factory=dict)

    def line(self) -> str:
        s = f"[{self.time}] {self.kind:<10} {self.who}: {self.message}"
        for label, (old, new) in self.diffs.items():
            s += f"\n{'':34}{label}: '{old}' -> '{new}'"
        return s

    def to_json(self) -> str:
        return json.dumps({
            "time": self.time, "kind": self.kind, "who": self.who,
            "message": self.message,
            "diffs": {k: {"antes": a, "ahora": b}
                      for k, (a, b) in self.diffs.items()},
        }, ensure_ascii=False)


class MonitorState:
    """Maquina de estados del monitoreo (pura, testeable sin capturar)."""

    def __init__(self, lost_after: int = 3):
        self.lost_after = lost_after
        self.known: Dict[tuple, NeighborInfo] = {}
        self.missed: Dict[tuple, int] = {}
        self.lost: Set[tuple] = set()
        self.cycle = 0

    @staticmethod
    def _now() -> str:
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    @staticmethod
    def _who(n: NeighborInfo) -> str:
        return n.switch_name or n.raw.get("chassis_id") or n.src_mac

    @staticmethod
    def _summary(n: NeighborInfo) -> str:
        parts = [f"puerto {n.port_id or '?'}"]
        if n.vlan:
            parts.append(f"VLAN {n.vlan}")
        if n.switch_ip:
            parts.append(f"IP {n.switch_ip}")
        return f"[{n.protocol}] " + ", ".join(parts)

    def update(self, neighbors: List[NeighborInfo]) -> List[MonitorEvent]:
        """Procesa el resultado de un ciclo de captura y devuelve eventos."""
        self.cycle += 1
        now = self._now()
        events: List[MonitorEvent] = []
        seen = {_key(n): n for n in neighbors}

        for k, n in seen.items():
            if k not in self.known:
                kind = "BASELINE" if self.cycle == 1 else "NUEVO"
                events.append(MonitorEvent(now, kind, self._who(n),
                                           self._summary(n)))
            else:
                old = self.known[k]
                diffs = {}
                for fname, label in _WATCH.items():
                    a, b = getattr(old, fname, ""), getattr(n, fname, "")
                    if a != b and (a or b):
                        diffs[label] = (a, b)
                if k in self.lost:
                    self.lost.discard(k)
                    events.append(MonitorEvent(
                        now, "RECUPERADO", self._who(n),
                        self._summary(n), diffs))
                elif diffs:
                    events.append(MonitorEvent(
                        now, "CAMBIO", self._who(n),
                        "cambio detectado", diffs))
            self.known[k] = n
            self.missed[k] = 0

        # Vecinos conocidos que no aparecieron en este ciclo
        for k, n in self.known.items():
            if k in seen or k in self.lost:
                continue
            self.missed[k] = self.missed.get(k, 0) + 1
            if self.missed[k] >= self.lost_after:
                self.lost.add(k)
                events.append(MonitorEvent(
                    now, "PERDIDO", self._who(n),
                    f"sin anuncios en {self.missed[k]} ciclos seguidos "
                    "(¿cable desconectado, puerto apagado o CDP/LLDP "
                    "deshabilitado?)"))

        if self.cycle == 1 and not neighbors:
            events.append(MonitorEvent(
                now, "BASELINE", "(segmento)",
                "sin vecinos CDP/LLDP al iniciar; se avisara si aparece "
                "alguno"))
        return events


def run_monitor(nic=None, cycle: int = 60, lost_after: int = 3,
                on_event: Optional[Callable] = None,
                on_status: Optional[Callable] = None,
                poll: Optional[Callable] = None,
                stop: Optional[Callable[[], bool]] = None,
                workdir: Optional[str] = None) -> MonitorState:
    """
    Bucle de monitoreo: captura 'cycle' segundos, compara, emite eventos y
    repite hasta que 'stop()' devuelva True (o KeyboardInterrupt del llamador).

    'poll(sec)' se llama cada segundo dentro de cada captura; devolver True
    la corta antes (permite detener el monitoreo sin esperar el ciclo entero).
    """
    from .capture import Capturer
    from .parse import parse_pcapng

    log = on_status or (lambda m: None)
    emit = on_event or (lambda e: None)
    comp = nic.pktmon_id if (nic and nic.pktmon_id) else "nics"
    workdir = workdir or os.path.join(tempfile.gettempdir(), "ldwinpy")

    state = MonitorState(lost_after=lost_after)
    cap = Capturer(workdir, comp=comp, on_status=lambda m: None)

    while not (stop and stop()):
        log(f"Ciclo {state.cycle + 1}: escuchando CDP/LLDP {cycle}s ...")
        pcapng = cap.capture(duration=cycle, poll=poll)
        neighbors = parse_pcapng(pcapng)
        for ev in state.update(neighbors):
            emit(ev)
        log(f"Ciclo {state.cycle} completado: {len(neighbors)} vecino(s), "
            f"{len(state.lost)} perdido(s).")
    return state
