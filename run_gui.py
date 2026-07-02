"""Punto de entrada para la GUI (usado por PyInstaller y para lanzar directo)."""
import sys
from ldwin.gui import run_gui

if __name__ == "__main__":
    sys.exit(run_gui())
