"""
Interfaz grafica de LDWinPy (tkinter, sin dependencias externas).

Replica el flujo del LDWin original pero multimarca (CDP + LLDP) y con
exportacion a txt/csv/json. La captura corre en un hilo aparte para no
congelar la ventana.
"""
from __future__ import annotations

import ctypes
import os
import queue
import tempfile
import threading

import tkinter as tk
from tkinter import ttk, messagebox, filedialog

from . import __version__
from . import export


def _is_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


class LDWinApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title(f"LDWinPy {__version__} - Link Discovery (CDP + LLDP)")
        self.root.geometry("900x560")
        self.msgq: "queue.Queue[tuple]" = queue.Queue()
        self.neighbors = []
        self.nics = []
        self.capturer = None
        self.mon_stop = threading.Event()
        self.monitoring = False
        self._build()
        self._load_nics()
        self.root.after(100, self._pump)

    # -- construccion de la UI ----------------------------------------------
    def _build(self):
        top = ttk.LabelFrame(self.root, text="Seleccion")
        top.pack(fill="x", padx=10, pady=8)

        ttk.Label(top, text="Tarjeta de red:").grid(row=0, column=0,
                                                     sticky="w", padx=6, pady=6)
        self.cbo = ttk.Combobox(top, state="readonly", width=70)
        self.cbo.grid(row=0, column=1, columnspan=3, sticky="we", padx=6)

        ttk.Label(top, text="Duracion (s):").grid(row=1, column=0,
                                                   sticky="w", padx=6, pady=6)
        self.spin = ttk.Spinbox(top, from_=5, to=180, width=6)
        self.spin.set(60)
        self.spin.grid(row=1, column=1, sticky="w", padx=6)

        self.btn_get = ttk.Button(top, text="Obtener datos de enlace",
                                  command=self._on_get)
        self.btn_get.grid(row=1, column=2, padx=6)
        self.btn_diag = ttk.Button(top, text="Diagnostico de enlace",
                                   command=self._on_diag)
        self.btn_diag.grid(row=1, column=3, padx=6)
        self.btn_mon = ttk.Button(top, text="Iniciar monitoreo",
                                  command=self._on_monitor)
        self.btn_mon.grid(row=1, column=5, padx=6)
        self.btn_save = ttk.Button(top, text="Guardar...",
                                   command=self._on_save, state="disabled")
        self.btn_save.grid(row=1, column=4, padx=6)
        top.columnconfigure(1, weight=1)

        res = ttk.LabelFrame(self.root, text="Resultados")
        res.pack(fill="both", expand=True, padx=10, pady=4)
        self.txt = tk.Text(res, wrap="none", font=("Consolas", 10))
        yscroll = ttk.Scrollbar(res, orient="vertical", command=self.txt.yview)
        self.txt.configure(yscrollcommand=yscroll.set)
        yscroll.pack(side="right", fill="y")
        self.txt.pack(fill="both", expand=True)

        bottom = ttk.Frame(self.root)
        bottom.pack(fill="x", padx=10, pady=6)
        self.status = ttk.Label(bottom, text="Listo.", anchor="w")
        self.status.pack(side="left")
        self.prog = ttk.Progressbar(bottom, mode="determinate", length=180)
        self.prog.pack(side="right")

        if not _is_admin():
            self._set_status("AVISO: sin privilegios de Administrador; "
                             "la captura fallara. Reinicia como Admin.")

    def _load_nics(self):
        def worker():
            try:
                from .nics import list_nics
                nics = list_nics()
            except Exception as e:
                self.msgq.put(("error", f"No se pudieron listar NICs: {e}"))
                return
            self.msgq.put(("nics", nics))
        threading.Thread(target=worker, daemon=True).start()

    # -- eventos -------------------------------------------------------------
    def _on_get(self):
        if not _is_admin():
            messagebox.showerror("Administrador requerido",
                                 "La captura requiere ejecutar como Administrador.")
            return
        if self.cbo.current() < 0:
            messagebox.showwarning("Seleccion", "Selecciona una tarjeta de red.")
            return
        try:
            duration = int(self.spin.get())
        except ValueError:
            duration = 60

        nic = self.nics[self.cbo.current()]
        comp = nic.pktmon_id or "nics"
        self.btn_get.configure(state="disabled")
        self.btn_save.configure(state="disabled")
        self.txt.delete("1.0", "end")
        self.prog.configure(maximum=duration, value=0)

        def worker():
            from .capture import Capturer, CaptureError
            from .parse import parse_pcapng
            workdir = os.path.join(tempfile.gettempdir(), "ldwinpy")
            self.capturer = Capturer(
                workdir, comp=comp,
                on_status=lambda m: self.msgq.put(("status", m)))
            try:
                def poll(sec):
                    self.msgq.put(("tick", sec))
                    return False
                pcapng = self.capturer.capture(duration=duration, poll=poll)
                neighbors = parse_pcapng(pcapng)
                self.msgq.put(("done", neighbors))
            except CaptureError as e:
                self.msgq.put(("error", str(e)))
            except Exception as e:  # noqa
                self.msgq.put(("error", f"Error inesperado: {e}"))

        threading.Thread(target=worker, daemon=True).start()

    def _on_diag(self):
        """Diagnostico: ¿switch administrable, no administrable o directo?"""
        if not _is_admin():
            messagebox.showerror("Administrador requerido",
                                 "El diagnostico requiere ejecutar como "
                                 "Administrador.")
            return
        if self.cbo.current() < 0:
            messagebox.showwarning("Seleccion", "Selecciona una tarjeta de red.")
            return
        try:
            duration = int(self.spin.get())
        except ValueError:
            duration = 45

        nic = self.nics[self.cbo.current()]
        self.btn_get.configure(state="disabled")
        self.btn_diag.configure(state="disabled")
        self.btn_save.configure(state="disabled")
        self.txt.delete("1.0", "end")
        self.prog.configure(maximum=duration, value=0)

        def worker():
            from .capture import CaptureError
            from .diag import run_diagnosis
            try:
                def poll(sec):
                    self.msgq.put(("tick", sec))
                    return False
                d = run_diagnosis(
                    nic=nic, duration=duration, poll=poll,
                    on_status=lambda m: self.msgq.put(("status", m)))
                self.msgq.put(("diag", d))
            except CaptureError as e:
                self.msgq.put(("error", str(e)))
            except Exception as e:  # noqa
                self.msgq.put(("error", f"Error inesperado: {e}"))

        threading.Thread(target=worker, daemon=True).start()

    def _on_monitor(self):
        """Alterna el monitoreo continuo (vigila cambios de puerto/VLAN)."""
        if self.monitoring:
            self.mon_stop.set()
            self.btn_mon.configure(state="disabled")
            self._set_status("Deteniendo monitoreo al final del ciclo...")
            return

        if not _is_admin():
            messagebox.showerror("Administrador requerido",
                                 "El monitoreo requiere ejecutar como "
                                 "Administrador.")
            return
        if self.cbo.current() < 0:
            messagebox.showwarning("Seleccion", "Selecciona una tarjeta de red.")
            return
        try:
            cycle = int(self.spin.get())
        except ValueError:
            cycle = 60

        nic = self.nics[self.cbo.current()]
        self.monitoring = True
        self.mon_stop.clear()
        self.btn_get.configure(state="disabled")
        self.btn_diag.configure(state="disabled")
        self.btn_save.configure(state="disabled")
        self.btn_mon.configure(text="Detener monitoreo")
        self.txt.delete("1.0", "end")
        self.txt.insert("end", f"=== MONITOREO INICIADO (ciclos de {cycle}s) "
                               f"===\n")
        self.prog.configure(maximum=cycle, value=0)

        def worker():
            from .capture import CaptureError
            from .monitor import run_monitor
            try:
                def poll(sec):
                    self.msgq.put(("tick", sec))
                    return self.mon_stop.is_set()   # corta el ciclo al detener
                run_monitor(
                    nic=nic, cycle=cycle,
                    on_event=lambda ev: self.msgq.put(("mon_event", ev)),
                    on_status=lambda m: self.msgq.put(("status", m)),
                    poll=poll, stop=self.mon_stop.is_set)
            except CaptureError as e:
                self.msgq.put(("error", str(e)))
            except Exception as e:  # noqa
                self.msgq.put(("error", f"Error inesperado: {e}"))
            finally:
                self.msgq.put(("mon_done", None))

        threading.Thread(target=worker, daemon=True).start()

    def _on_save(self):
        if not self.neighbors:
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Texto", "*.txt"), ("CSV", "*.csv"), ("JSON", "*.json")])
        if not path:
            return
        fmt = "txt"
        if path.lower().endswith(".csv"):
            fmt = "csv"
        elif path.lower().endswith(".json"):
            fmt = "json"
        try:
            export.write_file(path, self.neighbors, fmt)
            self._set_status(f"Guardado en {path}")
        except Exception as e:
            messagebox.showerror("Error al guardar", str(e))

    # -- cola de mensajes desde el hilo de captura ---------------------------
    def _pump(self):
        try:
            while True:
                kind, payload = self.msgq.get_nowait()
                if kind == "nics":
                    self.nics = payload
                    self.cbo["values"] = [n.label() for n in payload]
                    if payload:
                        self.cbo.current(0)
                    self._set_status(f"{len(payload)} tarjetas de red detectadas.")
                elif kind == "status":
                    self._set_status(payload)
                elif kind == "tick":
                    self.prog.configure(value=payload)
                    self._set_status(f"Escuchando CDP/LLDP... {payload}s")
                elif kind == "done":
                    self._finish(payload)
                elif kind == "diag":
                    self.neighbors = payload.neighbors
                    self.btn_get.configure(state="normal")
                    self.btn_diag.configure(state="normal")
                    if payload.neighbors:
                        self.btn_save.configure(state="normal")
                    self.prog.configure(value=self.prog["maximum"])
                    self.txt.delete("1.0", "end")
                    self.txt.insert("1.0", payload.report())
                    self._set_status(f"Diagnostico: {payload.verdict}")
                elif kind == "mon_event":
                    self.txt.insert("end", payload.line() + "\n")
                    self.txt.see("end")
                    if payload.kind != "BASELINE":
                        try:
                            import winsound
                            winsound.Beep(1200, 350)
                        except Exception:
                            pass
                elif kind == "mon_done":
                    self.monitoring = False
                    self.mon_stop.clear()
                    self.btn_mon.configure(text="Iniciar monitoreo",
                                           state="normal")
                    self.btn_get.configure(state="normal")
                    self.btn_diag.configure(state="normal")
                    self.prog.configure(value=0)
                    self.txt.insert("end", "=== MONITOREO DETENIDO ===\n")
                    self.txt.see("end")
                    self._set_status("Monitoreo detenido.")
                elif kind == "error":
                    self.btn_get.configure(state="normal")
                    self.btn_diag.configure(state="normal")
                    self.prog.configure(value=0)
                    self._set_status("Error.")
                    messagebox.showerror("Error", payload)
        except queue.Empty:
            pass
        self.root.after(100, self._pump)

    def _finish(self, neighbors):
        self.neighbors = neighbors
        self.btn_get.configure(state="normal")
        self.btn_diag.configure(state="normal")
        self.prog.configure(value=self.prog["maximum"])
        text = export.to_text(neighbors)
        self.txt.delete("1.0", "end")
        self.txt.insert("1.0", text)
        if neighbors:
            self.btn_save.configure(state="normal")
            self._set_status(f"{len(neighbors)} vecino(s) descubierto(s).")
        else:
            self._set_status("Sin anuncios CDP/LLDP. Prueba mayor duracion.")

    def _set_status(self, msg):
        self.status.configure(text=msg)


def run_gui() -> int:
    root = tk.Tk()
    try:
        root.iconify(); root.deiconify()
    except Exception:
        pass
    LDWinApp(root)
    root.mainloop()
    return 0


if __name__ == "__main__":
    run_gui()
