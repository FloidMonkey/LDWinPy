"""
LDWinPy - Link Discovery para Windows (CDP + LLDP multimarca).

Descubre a que switch y puerto esta conectado este equipo, capturando
anuncios CDP (Cisco/Mikrotik) y LLDP (Cisco, Mikrotik, TP-Link Omada,
D-Link y cualquier switch que hable el estandar).

Ejemplos:
    python -m ldwin --list                       # listar tarjetas de red
    python -m ldwin                               # capturar en todas las NICs 60s
    python -m ldwin -n "Ethernet" -t 90           # NIC y duracion especificas
    python -m ldwin --pcap captura.pcapng         # parsear un pcapng existente
    python -m ldwin -o resultado.json -f json     # exportar a JSON
"""
from __future__ import annotations

import argparse
import ctypes
import os
import sys
import tempfile

from . import __version__


def _is_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def _print(msg: str) -> None:
    print(msg, flush=True)


def _cmd_list() -> int:
    from .nics import list_nics
    nics = list_nics()
    if not nics:
        _print("No se encontraron tarjetas de red.")
        return 1
    _print(f"{'#':<3}{'NIC':<22}{'IPv4':<16}{'MAC':<20}{'pktmon':<7}Descripcion")
    _print("-" * 100)
    for i, n in enumerate(nics):
        _print(f"{i:<3}{n.name[:21]:<22}{(n.ipv4 or '-'):<16}{n.mac:<20}"
               f"{(n.pktmon_id or '-'):<7}{n.description[:35]}")
    return 0


def _resolve_nic(name_or_idx):
    from .nics import list_nics
    nics = list_nics()
    if name_or_idx is None:
        return None            # todas las NICs
    if name_or_idx.isdigit():
        idx = int(name_or_idx)
        if 0 <= idx < len(nics):
            return nics[idx]
        raise SystemExit(f"Indice de NIC fuera de rango: {idx}")
    for n in nics:
        if name_or_idx.lower() in (n.name.lower(), n.description.lower()):
            return n
        if name_or_idx.lower() in n.name.lower():
            return n
    raise SystemExit(f"No se encontro la NIC: {name_or_idx}")


def _emit(neighbors, args) -> None:
    from . import export
    text = export.to_text(neighbors)
    _print("\n" + text)
    if args.output:
        export.write_file(args.output, neighbors, args.format)
        _print(f"Resultados guardados en: {args.output}  (formato {args.format})")


def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        prog="ldwin", description="Link Discovery para Windows (CDP + LLDP).")
    p.add_argument("--version", action="version",
                   version=f"LDWinPy {__version__}")
    p.add_argument("--list", action="store_true",
                   help="Listar tarjetas de red y salir.")
    p.add_argument("-n", "--nic", metavar="NIC|#",
                   help="Nombre o indice de la NIC (por defecto: todas).")
    p.add_argument("-t", "--time", type=int, default=60, metavar="SEG",
                   help="Segundos a escuchar (por defecto 60).")
    p.add_argument("--pcap", metavar="ARCHIVO",
                   help="Parsear un .pcapng existente en vez de capturar.")
    p.add_argument("-o", "--output", metavar="ARCHIVO",
                   help="Guardar resultados en archivo.")
    p.add_argument("-f", "--format", choices=["txt", "csv", "json"],
                   default="txt", help="Formato de salida (por defecto txt).")
    p.add_argument("--gui", action="store_true",
                   help="Abrir la interfaz grafica.")
    p.add_argument("--diag", action="store_true",
                   help="Diagnostico de enlace: detecta switch administrable, "
                        "NO administrable (inferido) o enlace directo. "
                        "Recomendado con -n para una NIC concreta.")
    p.add_argument("--monitor", action="store_true",
                   help="Monitoreo continuo: vigila en ciclos de -t segundos "
                        "y avisa si cambia el puerto/VLAN/IP, aparece un "
                        "vecino nuevo o se pierde uno. Ctrl+C para detener.")
    p.add_argument("--lost-after", type=int, default=3, metavar="N",
                   help="Ciclos sin anuncios para declarar PERDIDO un vecino "
                        "(por defecto 3).")
    p.add_argument("--beep", action="store_true",
                   help="Pitido al detectar cambios en modo monitoreo.")
    args = p.parse_args(argv)

    if args.gui:
        from .gui import run_gui
        return run_gui()

    # --- Modo offline: parsear un pcapng existente (no requiere admin) ---
    if args.pcap:
        from .parse import parse_pcapng
        if not os.path.exists(args.pcap):
            _print(f"No existe el archivo: {args.pcap}")
            return 1
        neighbors = parse_pcapng(args.pcap)
        _emit(neighbors, args)
        return 0 if neighbors else 2

    if args.list:
        if not _is_admin():
            _print("(Aviso: sin privilegios de administrador, el mapeo pktmon "
                   "puede aparecer vacio.)")
        return _cmd_list()

    # --- Captura en vivo: requiere admin ---
    if not _is_admin():
        _print("ERROR: la captura requiere privilegios de Administrador.\n"
               "Abre una terminal como Administrador y vuelve a ejecutar,\n"
               "o usa --pcap para parsear una captura existente.")
        return 3

    from .capture import Capturer, CaptureError
    from .parse import parse_pcapng

    nic = _resolve_nic(args.nic)

    # --- Modo diagnostico ---
    if args.diag:
        from .diag import run_diagnosis
        if nic:
            _print(f"Diagnosticando enlace de: {nic.label()}")
            if not nic.pktmon_id:
                _print("(Sin Id pktmon; se captura en todas las NICs — la "
                       "atribucion puede ser imprecisa.)")
        else:
            _print("AVISO: sin -n se diagnostican TODAS las NICs a la vez; "
                   "si hay varias conectadas la atribucion sera imprecisa.")
        try:
            d = run_diagnosis(nic=nic, duration=args.time, on_status=_print)
        except CaptureError as e:
            _print(f"ERROR de captura: {e}")
            return 4
        _print("\n" + d.report())
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(d.report())
            _print(f"Diagnostico guardado en: {args.output}")
        return 0

    # --- Modo monitoreo continuo ---
    if args.monitor:
        from .monitor import run_monitor
        if nic:
            _print(f"Monitoreando: {nic.label()}")
        else:
            _print("Monitoreando TODAS las NICs (usa -n para una concreta).")
        _print(f"Ciclos de {args.time}s; un vecino se declara PERDIDO tras "
               f"{args.lost_after} ciclos sin anunciarse. Ctrl+C para "
               "detener.\n")

        logf = open(args.output, "a", encoding="utf-8") if args.output else None

        def on_event(ev):
            _print(ev.line())
            if args.beep and ev.kind != "BASELINE":
                try:
                    import winsound
                    winsound.Beep(1200, 350)
                except Exception:
                    pass
            if logf:
                logf.write((ev.to_json() if args.format == "json"
                            else ev.line()) + "\n")
                logf.flush()

        try:
            run_monitor(nic=nic, cycle=args.time,
                        lost_after=args.lost_after,
                        on_event=on_event, on_status=_print)
        except KeyboardInterrupt:
            _print("\nMonitoreo detenido por el usuario.")
        finally:
            if logf:
                logf.close()
                _print(f"Registro de eventos en: {args.output}")
        return 0
    comp = nic.pktmon_id if (nic and nic.pktmon_id) else "nics"
    if nic:
        _print(f"NIC seleccionada: {nic.label()}")
        if not nic.pktmon_id:
            _print("(No se pudo mapear el Id pktmon de la NIC; se captura en "
                   "todas las NICs.)")
    else:
        _print("Capturando en todas las tarjetas de red.")

    workdir = os.path.join(tempfile.gettempdir(), "ldwinpy")
    cap = Capturer(workdir, comp=comp, on_status=_print)
    try:
        pcapng = cap.capture(duration=args.time)
    except CaptureError as e:
        _print(f"ERROR de captura: {e}")
        return 4

    neighbors = parse_pcapng(pcapng)
    _emit(neighbors, args)
    if not neighbors:
        _print("No se recibieron anuncios CDP/LLDP. Algunos switches los "
               "emiten cada 30-60s; intenta con -t 90.")
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
