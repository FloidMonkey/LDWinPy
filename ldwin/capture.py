"""
Captura de frames CDP / LLDP usando pktmon (nativo de Windows 10 1809+/11).

No requiere instalar drivers (a diferencia de Npcap/WinPcap). El flujo es:

    1. Agregar filtros pktmon: ethertype 0x88CC (LLDP) y MAC 01:00:0C:CC:CC:CC (CDP)
    2. pktmon start --capture --pkt-size 0   (frame L2 completo)
    3. esperar N segundos a que el switch emita su anuncio
    4. pktmon stop
    5. pktmon etl2pcap  ->  .pcapng   (lo lee scapy)

Requiere privilegios de Administrador.
"""
from __future__ import annotations

import os
import subprocess
import time
from typing import List, Optional

LLDP_ETHERTYPE = 0x88CC            # 35020
CDP_MULTICAST = "01:00:0C:CC:CC:CC"
LLDP_MULTICAST = "01:80:C2:00:00:0E"

_FILTER_LLDP = "LDWin-LLDP"
_FILTER_CDP = "LDWin-CDP"


class CaptureError(RuntimeError):
    pass


def _run(args: List[str], check: bool = False) -> subprocess.CompletedProcess:
    """Ejecuta pktmon capturando salida. No lanza por defecto."""
    proc = subprocess.run(
        args, capture_output=True, text=True,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if check and proc.returncode != 0:
        raise CaptureError(
            f"Comando fallo ({proc.returncode}): {' '.join(args)}\n"
            f"{proc.stdout}\n{proc.stderr}")
    return proc


def is_pktmon_available() -> bool:
    from shutil import which
    return which("pktmon") is not None


class Capturer:
    """Orquesta una sesion de captura pktmon y la convierte a pcapng."""

    def __init__(self, workdir: str, comp: str = "nics",
                 max_mb: int = 64, on_status=None,
                 include_broadcast: bool = False):
        self.workdir = workdir
        self.comp = comp                 # 'all' | 'nics' | id numerico
        self.max_mb = max_mb
        self.include_broadcast = include_broadcast  # + ARP/broadcast (diagnostico)
        self.etl = os.path.join(workdir, "ldwin_capture.etl")
        self.pcapng = os.path.join(workdir, "ldwin_capture.pcapng")
        self._log = on_status or (lambda m: None)
        os.makedirs(workdir, exist_ok=True)

    # -- helpers -------------------------------------------------------------
    def _pktmon(self, *args, check=False):
        return _run(["pktmon", *args], check=check)

    def _reset_state(self):
        """Detiene cualquier sesion previa y limpia archivos antiguos."""
        self._pktmon("stop")                      # ignora si no habia sesion
        self._pktmon("filter", "remove")          # limpia filtros previos
        for f in (self.etl, self.pcapng):
            try:
                if os.path.exists(f):
                    os.remove(f)
            except OSError:
                pass

    def _add_filters(self) -> bool:
        """
        Agrega filtros LLDP (ethertype 0x88CC) y CDP (MAC multicast).
        Devuelve True si al menos uno de cada protocolo quedo activo.
        Si NINGUN filtro se pudo agregar, lo indica al llamador para que
        decida (capturar sin filtro produciria un .etl enorme).
        """
        # El ethertype puede aceptarse en decimal o hex segun la build de pktmon.
        lldp_ok = False
        for val in (str(LLDP_ETHERTYPE), hex(LLDP_ETHERTYPE)):
            if self._pktmon("filter", "add", _FILTER_LLDP, "-d", val).returncode == 0:
                lldp_ok = True
                break
        cdp_ok = self._pktmon("filter", "add", _FILTER_CDP,
                              "-m", CDP_MULTICAST).returncode == 0
        if not (lldp_ok or cdp_ok):
            raise CaptureError(
                "No se pudieron agregar filtros pktmon (¿ejecutas como "
                "Administrador?). Se aborta para no capturar todo el trafico.")
        if not lldp_ok:
            self._log("AVISO: no se pudo filtrar LLDP; solo se capturara CDP.")
        if not cdp_ok:
            self._log("AVISO: no se pudo filtrar CDP; solo se capturara LLDP.")
        if self.include_broadcast:
            # Para el diagnostico: ver quien mas "habla" en el segmento.
            self._pktmon("filter", "add", "LDWin-ARP", "-d", "2054")   # 0x0806
            self._pktmon("filter", "add", "LDWin-BCAST",
                         "-m", "FF:FF:FF:FF:FF:FF")
        return True

    # -- API -----------------------------------------------------------------
    def capture(self, duration: int = 60, poll=None) -> str:
        """
        Captura durante 'duration' segundos y devuelve la ruta del .pcapng.
        'poll' (opcional) es una funcion llamada cada segundo con los segundos
        transcurridos; si devuelve True, la captura se detiene antes.
        """
        if not is_pktmon_available():
            raise CaptureError("pktmon no esta disponible en este sistema "
                               "(requiere Windows 10 1809+ / Windows 11).")

        self._reset_state()
        self._add_filters()

        start = self._pktmon(
            "start", "--capture", "--pkt-size", "0",
            "--comp", self.comp, "--file-name", self.etl,
            "--file-size", str(self.max_mb), "--log-mode", "circular",
        )
        if start.returncode != 0:
            self._pktmon("filter", "remove")
            raise CaptureError(
                "No se pudo iniciar pktmon (¿ejecutas como Administrador?):\n"
                f"{start.stdout}\n{start.stderr}")

        self._log(f"Escuchando CDP/LLDP durante {duration}s ...")
        try:
            for sec in range(1, duration + 1):
                time.sleep(1)
                if poll and poll(sec):
                    self._log("Detenido por el usuario.")
                    break
        finally:
            self._pktmon("stop")
            self._pktmon("filter", "remove")

        return self._convert()

    def _convert(self) -> str:
        if not os.path.exists(self.etl):
            raise CaptureError("pktmon no genero archivo de captura (.etl).")
        conv = self._pktmon("etl2pcap", self.etl, "--out", self.pcapng)
        if conv.returncode != 0 or not os.path.exists(self.pcapng):
            raise CaptureError(
                f"Fallo la conversion a pcapng:\n{conv.stdout}\n{conv.stderr}")
        self._log("Captura convertida a pcapng.")
        return self.pcapng


def list_nic_components() -> List[dict]:
    """
    Parsea 'pktmon list' para mapear NIC -> Id de componente pktmon.
    Devuelve [{id, name, mac}]. Requiere admin.
    """
    proc = _run(["pktmon", "list"])
    if proc.returncode != 0:
        return []
    comps = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        # Formato tipico:  <Id>   <MAC>   <Nombre de la NIC>
        parts = line.split()
        if len(parts) >= 2 and parts[0].isdigit():
            comps.append({
                "id": parts[0],
                "mac": parts[1] if ":" in parts[1] or "-" in parts[1] else "",
                "name": " ".join(parts[2:]) if len(parts) > 2 else "",
            })
    return comps
