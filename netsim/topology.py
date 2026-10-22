"""Modelo da rede simulada: nós, interfaces, rotas e segmentos de enlace."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field


@dataclass
class Interface:
    name: str
    ip: str
    prefix: int
    mac: str
    segment: str

    @property
    def network(self) -> ipaddress.IPv4Network:
        return ipaddress.ip_interface(f"{self.ip}/{self.prefix}").network


@dataclass
class Route:
    network: str
    via: str | None  # None = rede diretamente conectada
    iface: str


@dataclass
class Node:
    id: str
    name: str
    kind: str  # host | switch | router | dns | server
    short: str
    x: int
    y: int
    interfaces: list[Interface] = field(default_factory=list)
    routes: list[Route] = field(default_factory=list)
    nat: str | None = None  # nome da interface WAN, se o nó faz NAT
    dns: str | None = None  # servidor DNS configurado
    services: tuple[str, ...] = ()
    label: str = "below"
    about: str = ""

    def iface(self, name: str) -> Interface:
        return next(i for i in self.interfaces if i.name == name)

    def has_ip(self, ip: str) -> bool:
        return any(i.ip == ip for i in self.interfaces)

    def lookup(self, dst: str) -> Route | None:
        """Roteamento por prefixo mais longo (longest prefix match)."""
        addr = ipaddress.IPv4Address(dst)
        matches = [r for r in self.routes if addr in ipaddress.ip_network(r.network)]
        return max(matches, key=lambda r: ipaddress.ip_network(r.network).prefixlen, default=None)


@dataclass
class Segment:
    id: str
    members: list[tuple[Node, Interface]] = field(default_factory=list)
    switch: str | None = None

    def port_of(self, node_id: str) -> int:
        return next(n for n, (node, _) in enumerate(self.members, start=1) if node.id == node_id)


class Topology:
    def __init__(self) -> None:
        self.nodes: dict[str, Node] = {}
        self.segments: dict[str, Segment] = {}
        self.zones: list[dict] = []

    def add(self, node: Node) -> None:
        self.nodes[node.id] = node
        for iface in node.interfaces:
            self.segments.setdefault(iface.segment, Segment(iface.segment)).members.append((node, iface))

    def owner(self, ip: str) -> Node | None:
        return next((n for n in self.nodes.values() if n.has_ip(ip)), None)

    def find_on_segment(self, segment: str, ip: str) -> tuple[Node, Interface] | None:
        return next(((n, i) for n, i in self.segments[segment].members if i.ip == ip), None)

    def to_dict(self) -> dict:
        links = []
        for seg in self.segments.values():
            network = str(seg.members[0][1].network)
            if seg.switch:
                links += [{"a": seg.switch, "b": node.id, "network": network} for node, _ in seg.members]
            else:
                (a, _), (b, _) = seg.members
                links.append({"a": a.id, "b": b.id, "network": network})
        nodes = [
            {
                "id": n.id,
                "name": n.name,
                "kind": n.kind,
                "short": n.short,
                "x": n.x,
                "y": n.y,
                "label": n.label,
                "about": n.about,
                "nat": n.nat,
                "interfaces": [
                    {"name": i.name, "ip": i.ip, "prefix": i.prefix, "mac": i.mac, "network": str(i.network)}
                    for i in n.interfaces
                ],
                "routes": [{"network": r.network, "via": r.via, "iface": r.iface} for r in n.routes],
            }
            for n in self.nodes.values()
        ]
        return {"nodes": nodes, "links": links, "zones": self.zones, "width": 1080, "height": 400}


def build_topology() -> Topology:
    """Casa (rede privada + NAT) -> provedor -> backbone -> datacenter.

    A "Internet" usa as faixas reservadas para documentação (RFC 5737).
    """
    t = Topology()
    y = 190

    t.add(Node(
        "pc", "Seu computador", "host", "PC", 70, y,
        [Interface("eth0", "192.168.0.10", 24, "02:00:00:00:00:10", "lan")],
        [Route("192.168.0.0/24", None, "eth0"), Route("0.0.0.0/0", "192.168.0.1", "eth0")],
        dns="203.0.113.130",
        about="Máquina de origem. Tem um IP privado, uma máscara, um gateway padrão e um servidor DNS configurados.",
    ))
    t.add(Node(
        "sw", "Switch", "switch", "SW", 210, y,
        label="above",
        about="Equipamento de camada 2: encaminha quadros pelo endereço MAC e não altera o pacote IP. "
              "Em casa, costuma estar embutido no próprio roteador.",
    ))
    t.add(Node(
        "nas", "Servidor local", "server", "SRV", 210, 335,
        [Interface("eth0", "192.168.0.20", 24, "02:00:00:00:00:20", "lan")],
        [Route("192.168.0.0/24", None, "eth0"), Route("0.0.0.0/0", "192.168.0.1", "eth0")],
        services=("http",), label="right",
        about="Servidor HTTP na mesma rede do computador: a entrega é direta, sem passar por roteador.",
    ))
    t.add(Node(
        "r1", "Roteador de casa", "router", "R1", 360, y,
        [Interface("lan", "192.168.0.1", 24, "02:00:00:00:01:01", "lan"),
         Interface("wan", "203.0.113.2", 30, "02:00:00:00:01:02", "acesso")],
        [Route("192.168.0.0/24", None, "lan"), Route("203.0.113.0/30", None, "wan"),
         Route("0.0.0.0/0", "203.0.113.1", "wan")],
        nat="wan",
        about="Gateway padrão da rede local. Faz NAT (PAT): troca o IP privado de origem pelo seu IP público.",
    ))
    t.add(Node(
        "r2", "Roteador ISP", "router", "R2", 520, y,
        [Interface("eth0", "203.0.113.1", 30, "02:00:00:00:02:01", "acesso"),
         Interface("eth1", "203.0.113.129", 30, "02:00:00:00:02:02", "dnsnet"),
         Interface("eth2", "198.51.100.1", 30, "02:00:00:00:02:03", "bb1")],
        [Route("203.0.113.0/30", None, "eth0"), Route("203.0.113.128/30", None, "eth1"),
         Route("198.51.100.0/30", None, "eth2"), Route("0.0.0.0/0", "198.51.100.2", "eth2")],
        about="Roteador do provedor de acesso. Liga os clientes ao backbone e à rede do servidor DNS.",
    ))
    t.add(Node(
        "dns", "Servidor DNS", "dns", "DNS", 520, 55,
        [Interface("eth0", "203.0.113.130", 30, "02:00:00:00:00:53", "dnsnet")],
        [Route("203.0.113.128/30", None, "eth0"), Route("0.0.0.0/0", "203.0.113.129", "eth0")],
        label="right",
        about="Resolvedor de nomes: traduz nomes como www.exemplo.com.br em endereços IPv4 (UDP porta 53).",
    ))
    t.add(Node(
        "r3", "Backbone", "router", "R3", 680, y,
        [Interface("eth0", "198.51.100.2", 30, "02:00:00:00:03:01", "bb1"),
         Interface("eth1", "198.51.100.5", 30, "02:00:00:00:03:02", "bb2")],
        [Route("198.51.100.0/30", None, "eth0"), Route("198.51.100.4/30", None, "eth1"),
         Route("203.0.113.0/24", "198.51.100.1", "eth0"), Route("192.0.2.0/24", "198.51.100.6", "eth1")],
        about="Roteador de núcleo da Internet. Não tem rota padrão: só encaminha para redes que conhece.",
    ))
    t.add(Node(
        "r4", "Borda do datacenter", "router", "R4", 840, y,
        [Interface("eth0", "198.51.100.6", 30, "02:00:00:00:04:01", "bb2"),
         Interface("eth1", "192.0.2.1", 24, "02:00:00:00:04:02", "dc")],
        [Route("198.51.100.4/30", None, "eth0"), Route("192.0.2.0/24", None, "eth1"),
         Route("0.0.0.0/0", "198.51.100.5", "eth0")],
        about="Último roteador do caminho: está diretamente conectado à rede do servidor web.",
    ))
    t.add(Node(
        "srv", "Servidor web", "server", "WEB", 990, y,
        [Interface("eth0", "192.0.2.80", 24, "02:00:00:00:00:80", "dc")],
        [Route("192.0.2.0/24", None, "eth0"), Route("0.0.0.0/0", "192.0.2.1", "eth0")],
        services=("http",),
        about="Servidor HTTP de www.exemplo.com.br, escutando na porta TCP 80.",
    ))

    t.segments["lan"].switch = "sw"
    t.zones = [
        {"label": "Rede local (casa)", "x": 14, "y": 14, "w": 412, "h": 372},
        {"label": "Internet", "x": 440, "y": 14, "w": 316, "h": 372},
        {"label": "Datacenter", "x": 770, "y": 14, "w": 296, "h": 372},
    ]
    return t
