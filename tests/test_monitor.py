"""
Validacion offline de la maquina de estados del monitoreo continuo.
Simula ciclos de captura sin hardware: baseline, cambio de puerto/VLAN,
vecino perdido, recuperado y nuevo.

Ejecutar:  python tests/test_monitor.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ldwin.monitor import MonitorState
from ldwin.parse import NeighborInfo


def sw(name="SG3452-SISTEMAS", port="gigabitEthernet 1/0/33", vlan="1",
       ip="192.168.106.142", chassis="6c:4c:bc:c9:f2:cb",
       src="6c:4c:bc:c9:f2:cb"):
    n = NeighborInfo(protocol="LLDP", switch_name=name, port_id=port,
                     vlan=vlan, switch_ip=ip, src_mac=src)
    n.raw["chassis_id"] = chassis
    return n


def kinds(events):
    return [e.kind for e in events]


def test_full_scenario():
    st = MonitorState(lost_after=3)

    # Ciclo 1: baseline
    ev = st.update([sw()])
    assert kinds(ev) == ["BASELINE"], kinds(ev)

    # Ciclo 2: sin cambios -> sin eventos
    ev = st.update([sw()])
    assert ev == [], kinds(ev)

    # Ciclo 3: nos cambiaron de puerto y de VLAN (misma chassis, otra src MAC)
    ev = st.update([sw(port="gigabitEthernet 1/0/45", vlan="200",
                       src="6c:4c:bc:c9:f2:d0")])
    assert kinds(ev) == ["CAMBIO"], kinds(ev)
    assert "Puerto" in ev[0].diffs and "VLAN" in ev[0].diffs
    assert ev[0].diffs["Puerto"] == ("gigabitEthernet 1/0/33",
                                     "gigabitEthernet 1/0/45")
    print("OK cambio de puerto:", ev[0].line().splitlines()[0])

    # Ciclos 4-5: el switch no aparece (aun no se declara perdido)
    assert st.update([]) == []
    assert st.update([]) == []

    # Ciclo 6: tercer ciclo sin anuncios -> PERDIDO
    ev = st.update([])
    assert kinds(ev) == ["PERDIDO"], kinds(ev)
    print("OK perdido:", ev[0].line().splitlines()[0])

    # Ciclo 7: vuelve a anunciarse -> RECUPERADO; ademas aparece uno NUEVO
    mikrotik = NeighborInfo(protocol="LLDP", switch_name="MikroTik_Sistemas",
                            port_id="bridge1/ether2", src_mac="c4:ad:34:09:63:77")
    mikrotik.raw["chassis_id"] = "c4:ad:34:09:63:75"
    ev = st.update([sw(port="gigabitEthernet 1/0/45", vlan="200"), mikrotik])
    assert sorted(kinds(ev)) == ["NUEVO", "RECUPERADO"], kinds(ev)
    print("OK recuperado + nuevo:",
          " | ".join(e.line().splitlines()[0] for e in ev))

    # Ciclo 8: estabilidad -> sin eventos
    assert st.update([sw(port="gigabitEthernet 1/0/45", vlan="200"),
                      mikrotik]) == []

    # JSON serializable
    import json
    for e in ev:
        json.loads(e.to_json())
    print("OK serializacion JSON")


def test_empty_baseline():
    st = MonitorState()
    ev = st.update([])
    assert kinds(ev) == ["BASELINE"] and "sin vecinos" in ev[0].message
    # luego aparece uno -> NUEVO
    ev = st.update([sw()])
    assert kinds(ev) == ["NUEVO"], kinds(ev)
    print("OK baseline vacio -> nuevo")


if __name__ == "__main__":
    test_full_scenario()
    test_empty_baseline()
    print("\nTodos los tests de monitoreo pasaron.")
