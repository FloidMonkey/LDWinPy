# LDWinPy — Link Discovery para Windows (CDP + LLDP, multimarca)

**¿A qué switch y a qué puerto está conectado este equipo?** LDWinPy captura
los anuncios de descubrimiento de enlace (CDP y LLDP) que emiten los switches
directamente conectados y te lo dice en segundos — sin bases de datos de
cableado, sin rastrear cables bajo el piso.

LDWinPy es una **reescritura moderna en Python** de las herramientas clásicas:

- [LDWin](https://github.com/chall32/LDWin) — Link Discovery for Windows (AutoIt)
- [WinCDP](https://github.com/chall32/WinCDP) — Cisco Discovery Protocol Client for Windows (AutoIt)

Ambas creadas por **Chris Hall** ([chall32](https://github.com/chall32)),
a quien corresponde el crédito del concepto original. LDWinPy conserva la idea
y la lleva mucho más lejos.

## ⚡ Ventajas frente al LDWin / WinCDP original

| | LDWin / WinCDP (AutoIt) | **LDWinPy** |
|---|---|---|
| **Instalación de drivers** | Requiere WinPcap/Npcap + `tcpdump.exe` embebido | ✅ **CERO drivers**: usa `pktmon`, nativo de Windows 10 1809+ / 11 |
| **Marcas soportadas** | Enfocado en Cisco | ✅ **Multimarca**: Cisco, MikroTik, TP-Link Omada, D-Link y cualquier equipo que hable LLDP |
| **Parseo de protocolo** | Texto de tcpdump con búsqueda de cadenas (frágil) | ✅ Disectores **scapy** robustos, TLV por TLV |
| **Datos obtenidos** | Nombre, puerto, VLAN, IP, modelo, dúplex, VTP | ✅ Todo eso **más**: descripción de sistema, firmware, capacidades, nombre de VLAN, **VLAN de voz (LLDP-MED)**, **PoE en vatios**, número de serie, MACs, TTL y TLVs crudos |
| **Switches NO administrables** | No aporta nada | ✅ **Diagnóstico por inferencia**: detecta la presencia probable de un switch no administrable o hub intermedio |
| **Monitoreo** | Captura única | ✅ **Monitoreo continuo**: avisa (con pitido y registro) si te cambian de puerto/VLAN, aparece un vecino nuevo o se pierde el enlace |
| **Salida** | TXT | ✅ **TXT / CSV / JSON** (integrable con inventarios y scripts) |
| **Interfaz** | Solo GUI | ✅ **CLI completa + GUI** |
| **Pruebas** | — | ✅ Suite de tests offline con paquetes sintéticos de cada marca |
| **Mantenibilidad** | AutoIt | ✅ Python 3 modular y documentado |

## 📥 Descarga

**[Descargar LDWin.exe (última versión)](../../releases/latest)** — un solo
archivo, sin dependencias: no necesita Python, ni scapy, ni drivers. Solo
Windows 10 1809+ / Windows 11 y privilegios de Administrador (los pide
automáticamente vía UAC).

## Uso rápido (CLI)

```powershell
# Listar tarjetas de red
python -m ldwin --list

# Capturar en todas las NICs durante 60s (como Administrador)
python -m ldwin

# NIC concreta (por índice o nombre) y 90 segundos
python -m ldwin -n "Ethernet" -t 90

# Exportar a JSON / CSV
python -m ldwin -o resultado.json -f json
python -m ldwin -o resultado.csv  -f csv

# Parsear una captura pcapng existente (no requiere admin)
python -m ldwin --pcap captura.pcapng

# Diagnóstico de enlace: ¿switch administrable, NO administrable o directo?
python -m ldwin --diag -n "Ethernet 6" -t 60

# Monitoreo continuo: avisa si cambia el puerto/VLAN o se pierde el switch
python -m ldwin --monitor -n "Ethernet" -t 60 --beep -o eventos.log
```

## GUI

```powershell
run_admin.bat        # doble clic; se auto-eleva a Administrador
python -m ldwin --gui
```

Tres modos desde la misma ventana: **Obtener datos de enlace**,
**Diagnóstico de enlace** y **Monitoreo continuo** (iniciar/detener).

## 🔍 Diagnóstico de switches NO administrables

Un switch no administrable no emite CDP/LLDP — no puede anunciarse. Pero
`--diag` **infiere su presencia** capturando además ARP/broadcast y razonando
sobre el segmento:

| Evidencia | Veredicto |
|---|---|
| Enlace activo + nadie anuncia CDP/LLDP + tráfico de ≥3 equipos | **Switch NO administrable** (probable) |
| Anuncios CDP/LLDP de **2+ equipos distintos** por el mismo puerto | **Dispositivo intermedio** (switch no administrable / hub) reenviando anuncios — un switch administrable solo enviaría el suyo |
| Un solo anunciante | Conectado a switch administrable |
| Enlace activo, sin anuncios ni tráfico | Enlace directo o segmento vacío |
| NIC reporta enlace abajo | Revisar cable/puerto |

También consulta el estado físico del enlace (`Get-NetAdapter`). Para mejor
atribución, usa `-n` con una NIC concreta.

## 📡 Monitoreo continuo (`--monitor`)

Vigila los anuncios en ciclos de `-t` segundos y emite eventos cuando algo
cambia:

| Evento | Significado |
|---|---|
| `BASELINE` | Estado inicial (primer ciclo) |
| `CAMBIO` | Te movieron de **puerto**, cambió la **VLAN**, IP, nombre, dúplex o PoE (con diff exacto `antes -> ahora`) |
| `NUEVO` | Apareció un vecino que no estaba |
| `PERDIDO` | Un vecino dejó de anunciarse N ciclos (`--lost-after`, def. 3) |
| `RECUPERADO` | Un vecino perdido volvió (con diff si volvió distinto) |

La identidad de cada vecino es su **chassis-id**, no la MAC del frame: si te
cambian de puerto se reporta como `CAMBIO` del mismo switch, no como un switch
nuevo. Con `--beep` (alerta sonora) y `-o eventos.log` (`-f json` para
JSON-lines integrable con otros sistemas).

## 📋 Datos LLDP-MED y PoE decodificados

Además de los TLV estándar, se decodifican los TLV **LLDP-MED** (TIA):
**VLAN de voz**, **PoE en vatios**, tipo de dispositivo e inventario
(**número de serie**, firmware, modelo), y la **clase PoE** del TLV 802.3
Power via MDI.

## Cómo funciona

1. `pktmon` (nativo de Windows) agrega filtros para **LLDP** (ethertype
   `0x88CC`) y **CDP** (MAC multicast `01:00:0C:CC:CC:CC`) y captura los
   frames L2 completos.
2. El `.etl` se convierte a `.pcapng` con `pktmon etl2pcap`.
3. `scapy` diseca cada frame (solo lectura de archivo — **no necesita driver
   de captura**) y `ldwin/parse.py` normaliza los campos de CDP y LLDP en una
   estructura única, sin importar la marca del switch.

## Requisitos (solo para ejecutar desde código)

- Windows 10 1809+ o Windows 11 (para `pktmon`)
- Python 3.9+ y `pip install -r requirements.txt` (solo scapy)
- Privilegios de Administrador para capturar

El `.exe` de [Releases](../../releases/latest) no requiere nada de esto.

## Compilar el .exe

```powershell
powershell -ExecutionPolicy Bypass -File build_exe.ps1
# Genera dist\LDWin.exe (manifiesto de Administrador incluido)
```

## Pruebas

El parser, el diagnóstico y el monitoreo se validan offline con paquetes
sintéticos de cada marca — no necesitan hardware, captura real ni admin:

```powershell
python tests/test_parse.py     # parseo CDP/LLDP de las 4 marcas
python tests/test_diag.py      # veredictos de diagnóstico + LLDP-MED
python tests/test_monitor.py   # máquina de estados del monitoreo
```

## Estructura

```
ldwin/
  parse.py     Disección/normalización CDP+LLDP (núcleo multimarca)
  capture.py   Wrapper de pktmon
  diag.py      Diagnóstico de enlace (switch no administrable, etc.)
  monitor.py   Monitoreo continuo de cambios
  nics.py      Enumeración de tarjetas de red
  export.py    TXT / CSV / JSON
  cli.py       Línea de comandos
  gui.py       Interfaz gráfica (tkinter)
tests/         Tests offline con paquetes sintéticos
```

## Créditos

- Concepto e inspiración: **Chris Hall** ([chall32](https://github.com/chall32)) con
  [LDWin](https://github.com/chall32/LDWin) / [WinCDP](https://github.com/chall32/WinCDP).
- LDWinPy es una **reimplementación independiente en Python** (scapy + pktmon); no
  contiene ni deriva del código de los proyectos originales, escritos en AutoIt.

## Licencia

Distribuido bajo la licencia **MIT**. Consulta el archivo [LICENSE](LICENSE)
para el texto completo.
