"""Exportacion de resultados a texto legible, CSV y JSON."""
from __future__ import annotations

import csv
import io
import json
from typing import List

from .parse import NeighborInfo

# Campos mostrados y su etiqueta legible (en el orden de presentacion)
FIELDS = [
    ("protocol", "Protocolo"),
    ("switch_name", "Nombre del Switch"),
    ("switch_ip", "IP del Switch"),
    ("port_id", "Puerto"),
    ("port_desc", "Descripcion del Puerto"),
    ("vlan", "VLAN"),
    ("vlan_name", "Nombre VLAN"),
    ("switch_model", "Modelo"),
    ("switch_desc", "Descripcion del Sistema"),
    ("switch_version", "Version / Firmware"),
    ("duplex", "Duplex"),
    ("capabilities", "Capacidades"),
    ("vtp_domain", "Dominio VTP"),
    ("power", "PoE"),
    ("src_mac", "MAC del Switch"),
    ("ttl", "TTL"),
]


def to_text(neighbors: List[NeighborInfo]) -> str:
    if not neighbors:
        return "No se encontraron vecinos CDP/LLDP.\n"
    out = io.StringIO()
    for i, n in enumerate(neighbors, 1):
        out.write(f"===== Vecino {i} ({n.protocol}) "
                  f"{'=' * 40}\n")
        for key, label in FIELDS:
            val = getattr(n, key, "")
            if val:
                out.write(f"  {label:24}: {val}\n")
        if n.raw:
            out.write("  --- datos crudos adicionales ---\n")
            for k, v in n.raw.items():
                out.write(f"  {k:24}: {v}\n")
        out.write("\n")
    return out.getvalue()


def to_csv(neighbors: List[NeighborInfo]) -> str:
    out = io.StringIO()
    keys = [k for k, _ in FIELDS]
    w = csv.writer(out, lineterminator="\n")
    w.writerow([label for _, label in FIELDS])
    for n in neighbors:
        w.writerow([getattr(n, k, "") for k in keys])
    return out.getvalue()


def to_json(neighbors: List[NeighborInfo]) -> str:
    return json.dumps([n.to_dict() for n in neighbors],
                      indent=2, ensure_ascii=False)


def write_file(path: str, neighbors: List[NeighborInfo], fmt: str) -> None:
    fmt = fmt.lower()
    if fmt == "csv":
        data = to_csv(neighbors)
    elif fmt == "json":
        data = to_json(neighbors)
    else:
        data = to_text(neighbors)
    with open(path, "w", encoding="utf-8-sig" if fmt == "csv" else "utf-8") as f:
        f.write(data)
