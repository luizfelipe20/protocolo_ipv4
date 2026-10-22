"""Motor da simulação: gera, passo a passo, os eventos de uma requisição HTTP sobre TCP/IPv4.

Cada evento é um passo exibido no frontend:
  - "node":    algo acontece dentro de um equipamento (encapsular, rotear, traduzir, entregar);
  - "transit": um quadro atravessa um enlace entre dois equipamentos.

Marcação usada nos textos: **negrito** e `código`.
"""

from __future__ import annotations

import copy
import ipaddress
import re
from dataclasses import dataclass

from . import ipv4
from .topology import Interface, Node, Topology, build_topology

BROADCAST = "ff:ff:ff:ff:ff:ff"
L4_HEADER = {6: 20, 17: 8, 1: 8}
MAX_HOPS = 32

DNS_ZONE = {"www.exemplo.com.br": "192.0.2.80", "exemplo.com.br": "192.0.2.80"}
HOSTNAME = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$")

FASE_DNS = "Resolução de nomes (DNS)"
FASE_SYN = "Abertura da conexão TCP"
FASE_HTTP = "Troca de dados HTTP"
FASE_FIN = "Encerramento da conexão TCP"


class SimulationError(ValueError):
    """Entrada inválida para a simulação."""


@dataclass
class Packet:
    src: str
    dst: str
    proto: int
    ttl: int
    ident: int
    l4: dict
    payload: dict | None = None

    @property
    def total_length(self) -> int:
        return 20 + L4_HEADER[self.proto] + (self.payload["length"] if self.payload else 0)


def _payload(kind: str, text: str) -> dict:
    return {"kind": kind, "text": text, "length": len(text.encode())}


class Simulation:
    def __init__(self, topo: Topology, dest: str, ttl: int) -> None:
        self.topo = topo
        self.dest = dest
        self.ttl = ttl
        self.events: list[dict] = []
        self.packets: list[dict] = []
        self.result: dict = {}
        self.phase = ""
        self.cur = 0
        self.last_frame: dict | None = None
        self.idents: dict[str, int] = {}
        self.mac_table: dict[str, int] = {}
        self.nat_out: dict[tuple, int] = {}
        self.nat_in: dict[tuple, tuple] = {}
        self.nat_next_port = 61001
        # Enlaces ponto a ponto já estão em uso: os vizinhos se conhecem. A rede com switch aprende ao vivo.
        self.arp: dict[str, dict[str, str]] = {n: {} for n in topo.nodes}
        for seg in topo.segments.values():
            if seg.switch:
                continue
            for node, _ in seg.members:
                for other, iface in seg.members:
                    if other.id != node.id:
                        self.arp[node.id][iface.ip] = iface.mac

    # ------------------------------------------------------------------ registro

    def _begin(self, label: str, tag: str, src: str, dst: str) -> None:
        self.packets.append({"label": label, "tag": tag, "phase": self.phase, "src": src, "dst": dst,
                             "first": len(self.events)})
        self.cur = len(self.packets) - 1

    def _emit(self, kind: str, title: str, details: list[str], layer: str, *, node: str | None = None,
              src: str | None = None, dst: str | None = None, also: list[str] | None = None,
              frame: dict | None = None, changes: list[str] | None = None, tables: list[dict] | None = None,
              calc: dict | None = None, status: str = "info") -> None:
        self.events.append({
            "id": len(self.events), "packet": self.cur, "kind": kind, "title": title, "details": details,
            "layer": layer, "node": node, "from": src, "to": dst, "also": also or [], "frame": frame,
            "changes": changes or [], "tables": tables or [], "calc": calc, "status": status,
        })

    def _ident(self, node_id: str) -> int:
        base = 0x1000 * (list(self.topo.nodes).index(node_id) + 1)
        self.idents[node_id] = self.idents.get(node_id, base) + 1
        return self.idents[node_id]

    def _frame(self, pkt: Packet, eth: dict | None = None) -> dict:
        header = ipv4.build_header(pkt.src, pkt.dst, pkt.proto, pkt.ttl, pkt.total_length, pkt.ident)
        return {
            "eth": eth,
            "ip": {
                "version": 4, "ihl": "5 (20 bytes)", "total_length": pkt.total_length,
                "identification": f"0x{pkt.ident:04x}", "flags": "DF (não fragmentar)", "ttl": pkt.ttl,
                "protocol": f"{pkt.proto} ({ipv4.PROTOCOLS[pkt.proto]})",
                "checksum": f"0x{int.from_bytes(header[10:12], 'big'):04x}",
                "src": pkt.src, "dst": pkt.dst, "hex": header.hex(" "),
            },
            "l4": copy.deepcopy(pkt.l4),
            "payload": pkt.payload,
        }

    # ------------------------------------------------------------------ tabelas

    def _route_table(self, node: Node, match) -> dict:
        rows = [[r.network, r.via or "diretamente conectada", r.iface] for r in node.routes]
        highlight = node.routes.index(match) if match else None
        return {"title": f"Tabela de rotas — {node.name}", "columns": ["Destino", "Próximo salto", "Interface"],
                "rows": rows, "highlight": highlight}

    def _arp_table(self, node: Node, ip: str | None = None) -> dict:
        items = list(self.arp[node.id].items())
        return {"title": f"Cache ARP — {node.name}", "columns": ["Endereço IP", "Endereço MAC"],
                "rows": [list(i) for i in items],
                "highlight": next((n for n, (k, _) in enumerate(items) if k == ip), None)}

    def _mac_table(self, mac: str | None = None) -> dict:
        items = list(self.mac_table.items())
        return {"title": "Tabela MAC — Switch", "columns": ["Endereço MAC", "Porta"],
                "rows": [[m, f"porta {p}"] for m, p in items],
                "highlight": next((n for n, (k, _) in enumerate(items) if k == mac), None)}

    def _nat_table(self, key: tuple | None = None) -> dict:
        keys = list(self.nat_out)
        public_ip = self.topo.nodes["r1"].iface("wan").ip
        return {"title": "Tabela NAT — Roteador de casa", "columns": ["Protocolo", "Interno (privado)", "Externo (público)"],
                "rows": [[p, f"{ip}:{port}", f"{public_ip}:{self.nat_out[(p, ip, port)]}"] for p, ip, port in keys],
                "highlight": keys.index(key) if key in keys else None}

    # ------------------------------------------------------------------ camada 2

    def _transmit(self, node: Node, egress: Interface, frame: dict, target: tuple[Node, Interface] | None,
                  broadcast: bool = False) -> None:
        """Leva um quadro de `node` até `target` pelo segmento da interface de saída."""
        seg = self.topo.segments[egress.segment]
        others = [(n, i) for n, i in seg.members if n.id != node.id]
        primary = target or (others[0] if others else None)
        signal = ("A placa de rede converte o quadro em sinais (elétricos, ópticos ou de rádio) e os transmite "
                  "bit a bit: é a **camada física**.")
        if not seg.switch:
            if primary:
                self._emit("transit", f"{node.name} → {primary[0].name}",
                           [signal, "É um enlace ponto a ponto: o quadro chega direto à interface vizinha."],
                           "fisica", src=node.id, dst=primary[0].id, frame=frame)
            return

        sw = self.topo.nodes[seg.switch]
        port = seg.port_of(node.id)
        self.mac_table[egress.mac] = port
        self._emit("transit", f"{node.name} → {sw.name}",
                   [signal, f"O switch recebe o quadro na porta {port} e **aprende** que o MAC `{egress.mac}` "
                            "está nessa porta."],
                   "fisica", src=node.id, dst=sw.id, frame=frame, tables=[self._mac_table(egress.mac)])
        if not primary:
            return
        dst_mac = frame["eth"]["dst"]
        note = "O switch é um equipamento de camada 2: não altera o quadro nem examina o cabeçalho IP."
        if broadcast or dst_mac not in self.mac_table:
            why = (f"O MAC de destino é o endereço de **broadcast** (`{BROADCAST}`)" if broadcast
                   else f"O MAC `{dst_mac}` ainda não está na tabela")
            self._emit("transit", f"{sw.name} → todas as portas",
                       [f"{why}: o switch faz **flooding**, repetindo o quadro em todas as portas, menos a de origem.",
                        note],
                       "enlace", src=sw.id, dst=primary[0].id,
                       also=[n.id for n, _ in others if n.id != primary[0].id], frame=frame,
                       tables=[self._mac_table()])
        else:
            self._emit("transit", f"{sw.name} → {primary[0].name}",
                       [f"O switch consulta a tabela MAC: `{dst_mac}` está na porta {self.mac_table[dst_mac]}, "
                        "então o quadro sai **somente** por essa porta.", note],
                       "enlace", src=sw.id, dst=primary[0].id, frame=frame, tables=[self._mac_table(dst_mac)])

    def _arp(self, node: Node, egress: Interface, target_ip: str) -> str | None:
        """Resolve IP -> MAC no segmento local. Devolve None se ninguém responder."""
        owner = self.topo.find_on_segment(egress.segment, target_ip)
        self._begin("ARP Request", "ARP", node.id, "broadcast")
        request = {"eth": {"src": egress.mac, "dst": BROADCAST, "type": "0x0806 (ARP)"},
                   "arp": {"op": "1 (request)", "sha": egress.mac, "spa": egress.ip,
                           "tha": "00:00:00:00:00:00", "tpa": target_ip}}
        self._emit("node", f"ARP: quem tem {target_ip}?",
                   ["O IP diz **para onde** o pacote vai; o Ethernet precisa do **endereço MAC** de quem recebe o quadro "
                    "neste enlace.",
                    f"{node.name} pergunta a toda a rede local: “quem tem `{target_ip}`? Responda para `{egress.ip}`”.",
                    "O ARP viaja direto dentro do quadro Ethernet (EtherType `0x0806`), sem cabeçalho IP."],
                   "enlace", node=node.id, frame=request, tables=[self._arp_table(node)])
        self._transmit(node, egress, request, owner, broadcast=True)
        if owner is None:
            self._emit("node", "Nenhuma resposta ao ARP",
                       [f"Nenhum equipamento deste enlace possui o IP `{target_ip}`.",
                        "Sem o MAC de destino não há como montar o quadro: o pacote é **descartado**."],
                       "enlace", node=node.id, status="drop")
            return None

        onode, oiface = owner
        self.arp[onode.id][egress.ip] = egress.mac
        self._begin("ARP Reply", "ARP", onode.id, node.id)
        reply = {"eth": {"src": oiface.mac, "dst": egress.mac, "type": "0x0806 (ARP)"},
                 "arp": {"op": "2 (reply)", "sha": oiface.mac, "spa": target_ip, "tha": egress.mac, "tpa": egress.ip}}
        self._emit("node", f"{onode.name} responde ao ARP",
                   [f"Todos receberam o broadcast, mas só o dono de `{target_ip}` responde; os demais ignoram.",
                    f"{onode.name} aproveita e guarda `{egress.ip}` → `{egress.mac}` no próprio cache ARP.",
                    f"A resposta é **unicast**: vai só para `{egress.mac}`."],
                   "enlace", node=onode.id, frame=reply, tables=[self._arp_table(onode, egress.ip)])
        self._transmit(onode, oiface, reply, (node, egress))
        self.arp[node.id][target_ip] = oiface.mac
        self._emit("node", "Cache ARP atualizado",
                   [f"{node.name} aprende que `{target_ip}` está em `{oiface.mac}` e guarda no cache ARP.",
                    "Os próximos quadros para esse vizinho não precisam de novo ARP enquanto a entrada for válida."],
                   "enlace", node=node.id, frame=reply, tables=[self._arp_table(node, target_ip)], status="ok")
        return oiface.mac

    # ------------------------------------------------------------------ NAT e ICMP

    def _nat_translate_out(self, egress: Interface, pkt: Packet, details: list, changes: list, tables: list) -> None:
        if pkt.proto == 1:
            return
        key = (ipv4.PROTOCOLS[pkt.proto], pkt.src, pkt.l4["sport"])
        if key not in self.nat_out:
            self.nat_out[key] = self.nat_next_port
            self.nat_in[(key[0], self.nat_next_port)] = (pkt.src, pkt.l4["sport"])
            self.nat_next_port += 1
            how = "cria uma entrada na tabela NAT"
        else:
            how = "reutiliza a entrada existente na tabela NAT"
        port = self.nat_out[key]
        details.append(f"**NAT (PAT)**: `{pkt.src}` é um IP privado, não roteável na Internet. O roteador {how} e troca "
                       f"a origem `{pkt.src}:{pkt.l4['sport']}` por `{egress.ip}:{port}` (seu IP público).")
        pkt.src, pkt.l4["sport"] = egress.ip, port
        changes += ["ip.src", "l4.sport"]
        tables.append(self._nat_table(key))

    def _nat_translate_in(self, pkt: Packet, details: list, changes: list, tables: list) -> None:
        embedded = pkt.l4.get("embedded")
        proto, port = (embedded["proto"], embedded["sport"]) if embedded else (ipv4.PROTOCOLS[pkt.proto], pkt.l4["dport"])
        inner = self.nat_in.get((proto, port))
        if inner is None:
            return
        key = (proto, *inner)
        if embedded:
            details.append("**NAT reverso**: a mensagem ICMP carrega o cabeçalho do pacote original; a porta "
                           f"`{port}` dele identifica a entrada NAT, e o destino vira `{inner[0]}`.")
            embedded["src"], embedded["sport"] = inner
        else:
            details.append(f"**NAT reverso**: a porta de destino `{port}` está na tabela NAT, então o destino "
                           f"`{pkt.dst}:{port}` volta a ser `{inner[0]}:{inner[1]}`.")
            pkt.l4["dport"] = inner[1]
            changes.append("l4.dport")
        pkt.dst = inner[0]
        changes.append("ip.dst")
        tables.append(self._nat_table(key))

    def _icmp_error(self, node: Node, ingress: Interface, orig: Packet, typ: int, code: int, desc: str) -> None:
        if orig.proto == 1:  # nunca se gera erro ICMP sobre outro erro ICMP
            return
        pkt = Packet(
            ingress.ip, orig.src, 1, 64, self._ident(node.id),
            {"kind": "ICMP", "type": typ, "code": code, "desc": desc,
             "embedded": {"src": orig.src, "dst": orig.dst, "proto": ipv4.PROTOCOLS[orig.proto],
                          "sport": orig.l4.get("sport"), "dport": orig.l4.get("dport")}},
            {"kind": "Dados ICMP", "text": "cabeçalho IPv4 do pacote descartado + seus 8 primeiros bytes de dados",
             "length": 28},
        )
        self._begin(f"ICMP {desc.split(' (')[0]}", "ICMP", node.id, orig.src)
        self._forward(node.id, pkt, f"{node.name} avisa a origem com ICMP",
                      [f"O roteador cria uma mensagem **ICMP tipo {typ}, código {code}: {desc}** endereçada à origem do "
                       f"pacote descartado (`{orig.src}`).",
                       "A mensagem leva uma cópia do cabeçalho IPv4 original, para a origem saber de qual pacote se trata."],
                      "rede")

    # ------------------------------------------------------------------ camada 3

    def _forward(self, origin_id: str, pkt: Packet, title: str, intro: list[str], layer: str) -> Node | None:
        """Encaminha o pacote salto a salto. Devolve o nó que o recebeu, ou None se foi descartado."""
        node = self.topo.nodes[origin_id]
        ingress: Interface | None = None
        for _ in range(MAX_HOPS):
            details: list[str] = []
            changes: list[str] = []
            tables: list[dict] = []
            calc = None

            if ingress is None:
                details += intro
                event_title, event_layer = title, layer
            else:
                if node.nat and ingress.name == node.nat and pkt.dst == ingress.ip:
                    self._nat_translate_in(pkt, details, changes, tables)
                if node.has_ip(pkt.dst):
                    self._deliver(node, pkt)
                    return node
                event_title, event_layer = f"{node.name}: roteamento", "rede"
                details.insert(0, f"O MAC de destino do quadro é o da interface `{ingress.name}`: o roteador remove o "
                                  "cabeçalho Ethernet e passa a examinar o cabeçalho IPv4.")
                details.insert(1, "Confere o checksum do cabeçalho: está íntegro. O IP de destino "
                                  f"`{pkt.dst}` não é dele, então o pacote deve ser **encaminhado**.")
                if pkt.ttl <= 1:
                    details.append(f"O TTL chegou com valor `{pkt.ttl}`; ao decrementar vira **0**. O pacote é "
                                   "**descartado** para não circular para sempre na rede.")
                    self._emit("node", f"{node.name}: TTL expirou", details, "rede", node=node.id,
                               frame=self.last_frame, changes=["ip.ttl"], tables=tables, status="drop")
                    self._icmp_error(node, ingress, pkt, 11, 0, "Time Exceeded (TTL expirado em trânsito)")
                    return None
                pkt.ttl -= 1
                changes += ["ip.ttl", "ip.checksum"]
                details.append(f"Decrementa o **TTL**: `{pkt.ttl + 1}` → `{pkt.ttl}`. Como o cabeçalho mudou, o "
                               "**checksum** é recalculado.")

            route = node.lookup(pkt.dst)
            tables.append(self._route_table(node, route))
            if route is None:
                details.append(f"Nenhuma linha da tabela de rotas cobre `{pkt.dst}` e não há rota padrão: o pacote é "
                               "**descartado**.")
                self._emit("node", f"{node.name}: sem rota para o destino", details, "rede", node=node.id,
                           frame=self._frame(pkt), changes=changes, tables=tables, status="drop")
                if ingress is not None:
                    self._icmp_error(node, ingress, pkt, 3, 0, "Destination Unreachable (rede inalcançável)")
                return None

            egress = node.iface(route.iface)
            next_ip = route.via or pkt.dst
            if ingress is None and node.kind != "router":
                calc = ipv4.and_calc(pkt.dst, egress.ip, egress.prefix)
                where = ("é a **mesma rede**: a entrega é direta, sem roteador" if calc["same"]
                         else f"é **outra rede**: o pacote vai para o gateway padrão `{next_ip}`")
                details.append(f"Decisão de rota: `{pkt.dst}` AND `{calc['mask']}` = `{calc['result']}`. A rede deste "
                               f"host é `{calc['own_network']}`, então {where}.")
            elif route.via:
                details.append(f"Tabela de rotas: a entrada mais específica para `{pkt.dst}` é `{route.network}`, via "
                               f"`{route.via}` pela interface `{route.iface}`.")
            else:
                details.append(f"Tabela de rotas: `{pkt.dst}` pertence a `{route.network}`, rede **diretamente "
                               f"conectada** à interface `{route.iface}`. O próximo salto é o próprio destino.")

            if node.nat and egress.name == node.nat and ingress is not None and ingress.name != node.nat:
                self._nat_translate_out(egress, pkt, details, changes, tables)
                changes.append("ip.checksum")

            mac = self.arp[node.id].get(next_ip)
            if mac is None:
                details.append(f"Para montar o quadro falta o MAC de `{next_ip}`, que não está no cache ARP. O pacote "
                               "fica em espera enquanto um **ARP Request** é enviado.")
                self._emit("node", event_title, details, event_layer, node=node.id, frame=self._frame(pkt),
                           changes=changes, tables=tables, calc=calc)
                waiting = self.cur
                mac = self._arp(node, egress, next_ip)
                if mac is None:
                    if ingress is not None:
                        self._icmp_error(node, ingress, pkt, 3, 1, "Destination Unreachable (host inalcançável)")
                    return None
                self.cur = waiting
                frame = self._frame(pkt, {"src": egress.mac, "dst": mac, "type": "0x0800 (IPv4)"})
                self._emit("node", f"{node.name}: quadro Ethernet montado",
                           [f"Com o MAC em mãos, o pacote que estava em espera é encapsulado num quadro Ethernet: origem "
                            f"`{egress.mac}`, destino `{mac}`.",
                            "Repare: o **IP de destino** continua sendo o do destino final; o **MAC de destino** é só o "
                            "do próximo salto."],
                           "enlace", node=node.id, frame=frame, changes=["eth.src", "eth.dst"],
                           tables=[self._arp_table(node, next_ip)])
            else:
                details.append(f"Cache ARP: `{next_ip}` → `{mac}`. O pacote é encapsulado num **novo quadro Ethernet** "
                               f"(origem `{egress.mac}`, destino `{mac}`) e sai pela interface `{egress.name}`.")
                frame = self._frame(pkt, {"src": egress.mac, "dst": mac, "type": "0x0800 (IPv4)"})
                if ingress is not None:
                    changes += ["eth.src", "eth.dst"]
                self._emit("node", event_title, details, event_layer, node=node.id, frame=frame, changes=changes,
                           tables=tables, calc=calc)

            self.last_frame = frame
            target = self.topo.find_on_segment(egress.segment, next_ip)
            self._transmit(node, egress, frame, target)
            node, ingress = target
        return None

    def _deliver(self, node: Node, pkt: Packet) -> None:
        l4 = pkt.l4
        details = [f"O IP de destino `{pkt.dst}` pertence a esta máquina: o pacote **chegou ao destino**.",
                   "Desencapsulamento: remove o Ethernet, confere o checksum IPv4 e entrega o conteúdo ao protocolo "
                   f"indicado no campo Protocolo (`{pkt.proto}` = {ipv4.PROTOCOLS[pkt.proto]})."]
        if pkt.proto == 6:
            details.append(f"O TCP usa a porta de destino `{l4['dport']}` para achar o socket. Flags recebidas: "
                           f"**{', '.join(l4['flags'])}**, seq=`{l4['seq']}`, ack=`{l4['ack']}`.")
        elif pkt.proto == 17:
            details.append(f"O UDP entrega os dados ao processo que escuta na porta `{l4['dport']}`.")
        else:
            details.append(f"Mensagem ICMP tipo {l4['type']}: **{l4['desc']}**. O sistema operacional repassa o erro "
                           "ao socket que enviou o pacote original.")
        if pkt.payload and pkt.proto != 1:
            details.append(f"Os dados ({pkt.payload['kind']}, {pkt.payload['length']} bytes) sobem para a aplicação.")
        layer = "aplicacao" if pkt.payload and pkt.proto != 1 else "transporte"
        self._emit("node", f"{node.name} recebe o pacote", details, layer, node=node.id, frame=self.last_frame,
                   status="drop" if pkt.proto == 1 else "ok")

    # ------------------------------------------------------------------ roteiro

    def _finish(self, ok: bool, title: str, details: list[str]) -> dict:
        self._emit("node", title, details, "aplicacao", node="pc", status="ok" if ok else "drop")
        self.result = {"ok": ok, "title": title, "summary": details[0]}
        return {"topology": self.topo.to_dict(), "packets": self.packets, "events": self.events,
                "result": self.result, "input": {"destino": self.dest, "ttl": self.ttl}}

    def _dns(self, host: str) -> tuple[str | None, str]:
        pc = self.topo.nodes["pc"]
        self.phase = FASE_DNS
        query = Packet(pc.interfaces[0].ip, pc.dns, 17, self.ttl, self._ident("pc"),
                       {"kind": "UDP", "sport": 53124, "dport": 53},
                       _payload("DNS", f"Consulta padrão\nPergunta: {host}  tipo A (endereço IPv4)  classe IN"))
        self._begin("DNS Query", "DNS", "pc", "dns")
        arrived = self._forward("pc", query, f"O navegador precisa do IP de {host}", [
            f"O usuário digitou `http://{host}/`. Pacotes IP são endereçados por número, não por nome: antes de tudo é "
            "preciso **resolver o nome**.",
            f"O sistema monta uma consulta DNS (tipo A) e a envia por **UDP** para a porta `53` do servidor DNS "
            f"configurado, `{pc.dns}`.",
            f"Encapsulamento: consulta DNS → datagrama UDP → pacote IPv4 com TTL `{self.ttl}`.",
        ], "aplicacao")
        if arrived is None:
            return None, "A consulta DNS não chegou ao servidor de nomes, então o nome não pôde ser resolvido."

        answer = DNS_ZONE.get(host)
        text = (f"Resposta padrão, sem erro\nResposta: {host}  A  {answer}  TTL 300 s" if answer
                else f"Resposta padrão\nCódigo: NXDOMAIN (o domínio {host} não existe)")
        response = Packet(pc.dns, query.src, 17, 64, self._ident("dns"),
                          {"kind": "UDP", "sport": 53, "dport": query.l4["sport"]}, _payload("DNS", text))
        self._begin("DNS Response", "DNS", "dns", "pc")
        self._forward("dns", response, "Servidor DNS responde", [
            (f"O servidor encontra o registro A: `{host}` → `{answer}`." if answer
             else f"O servidor não encontra nenhum registro para `{host}` e responde **NXDOMAIN**."),
            f"A resposta volta para o endereço de onde a consulta veio, `{query.src}:{query.l4['sport']}`: o IP "
            "público do roteador de casa, já que o NAT trocou a origem.",
        ], "aplicacao")
        if answer is None:
            return None, f"O nome `{host}` não existe no DNS (NXDOMAIN): sem endereço IP não há para onde enviar."
        return answer, ""

    def run(self) -> dict:
        pc = self.topo.nodes["pc"]
        pc_ip = pc.interfaces[0].ip
        try:
            ip, host = str(ipaddress.IPv4Address(self.dest)), None
        except ValueError:
            host = self.dest
            ip, error = self._dns(host)
            if ip is None:
                return self._finish(False, "Falha na resolução de nomes", [error])

        cport, cseq, sseq = 49152, 1000, 5000

        def client(flags: list[str], seq: int, ack: int, payload: dict | None = None) -> Packet:
            return Packet(pc_ip, ip, 6, self.ttl, self._ident("pc"),
                          {"kind": "TCP", "sport": cport, "dport": 80, "seq": seq, "ack": ack, "flags": flags,
                           "window": 64240}, payload)

        # --- three-way handshake
        self.phase = FASE_SYN
        syn = client(["SYN"], cseq, 0)
        self._begin("TCP SYN", "TCP", "pc", ip)
        target = self._forward("pc", syn, "TCP: pedido de conexão (SYN)", [
            (f"O DNS respondeu: `{host}` é `{ip}`." if host
             else f"O destino `{ip}` já é um endereço IPv4, então **não há consulta DNS**."),
            "O HTTP roda sobre TCP, que exige uma conexão antes de trocar dados. O primeiro passo do **three-way "
            f"handshake** é um segmento com a flag **SYN** para a porta `80`, a partir da porta efêmera `{cport}`.",
            f"O SYN leva o número de sequência inicial do cliente, seq=`{cseq}` (na prática é um valor aleatório de 32 bits).",
            f"Encapsulamento: segmento TCP → pacote IPv4 com TTL `{self.ttl}`.",
        ], "transporte")
        if target is None:
            return self._finish(False, "A conexão não foi estabelecida", [
                "O SYN foi descartado no caminho e nunca chegou ao destino.",
                "O TCP ainda retransmitiria o SYN algumas vezes antes de desistir; a aplicação veria um erro de "
                "rede inalcançável ou tempo esgotado.",
            ])

        peer_ip, peer_port = syn.src, syn.l4["sport"]

        def server(flags: list[str], seq: int, ack: int, payload: dict | None = None) -> Packet:
            return Packet(ip, peer_ip, 6, 64, self._ident(target.id),
                          {"kind": "TCP", "sport": 80, "dport": peer_port, "seq": seq, "ack": ack, "flags": flags,
                           "window": 65160}, payload)

        if "http" not in target.services:
            self._begin("TCP RST, ACK", "TCP", target.id, "pc")
            self._forward(target.id, server(["RST", "ACK"], 0, cseq + 1), "Porta fechada: resposta RST", [
                f"{target.name} não tem nenhum processo escutando na porta TCP `80`.",
                "O sistema operacional responde com a flag **RST** (reset), recusando a conexão na hora.",
            ], "transporte")
            return self._finish(False, "Conexão recusada", [
                f"O pacote chegou a `{ip}`, mas a porta 80 está fechada e o destino respondeu com TCP RST.",
                "Isso mostra a diferença entre alcançar a máquina (camada de rede) e haver um serviço na porta "
                "(camada de transporte).",
            ])

        seen = (f" Para o servidor, o cliente é `{peer_ip}:{peer_port}`: ele nunca vê o IP privado." if peer_ip != pc_ip else "")
        self._begin("TCP SYN, ACK", "TCP", target.id, "pc")
        self._forward(target.id, server(["SYN", "ACK"], sseq, cseq + 1), "TCP: servidor aceita (SYN, ACK)", [
            f"Há um processo escutando na porta `80`. O servidor responde com **SYN, ACK**: confirma o SYN do cliente "
            f"(ack=`{cseq + 1}`) e envia seu próprio número de sequência inicial (seq=`{sseq}`).{seen}",
        ], "transporte")
        self._begin("TCP ACK", "TCP", "pc", ip)
        self._forward("pc", client(["ACK"], cseq + 1, sseq + 1), "TCP: cliente confirma (ACK)", [
            f"O cliente confirma o SYN do servidor com ack=`{sseq + 1}`. **Conexão estabelecida** nos dois sentidos.",
            "A partir daqui os dados da aplicação podem ser enviados.",
        ], "transporte")

        # --- dados HTTP
        self.phase = FASE_HTTP
        name = host or ip
        request = _payload("HTTP", f"GET / HTTP/1.1\r\nHost: {name}\r\nUser-Agent: SimuladorRedes/1.0\r\nAccept: text/html\r\n\r\n")
        body = f"<html><body><h1>Olá de {name}!</h1></body></html>"
        reply = _payload("HTTP", "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n"
                                 f"Content-Length: {len(body.encode())}\r\n\r\n{body}")
        n, m = request["length"], reply["length"]

        self._begin("HTTP GET /", "HTTP", "pc", ip)
        self._forward("pc", client(["PSH", "ACK"], cseq + 1, sseq + 1, request), "HTTP: o navegador envia a requisição", [
            "A aplicação escreve a requisição HTTP no socket; o TCP a coloca num segmento com as flags **PSH, ACK**.",
            f"São `{n}` bytes de dados a partir de seq=`{cseq + 1}`. Encapsulamento completo: HTTP → TCP → IPv4 → Ethernet.",
        ], "aplicacao")
        self._begin("HTTP 200 OK", "HTTP", target.id, "pc")
        self._forward(target.id, server(["PSH", "ACK"], sseq + 1, cseq + 1 + n, reply), "HTTP: o servidor responde", [
            "O servidor web processa o `GET /` e devolve o código **200 OK** com a página.",
            f"O mesmo segmento confirma os `{n}` bytes recebidos (ack=`{cseq + 1 + n}`) e carrega `{m}` bytes de resposta.",
            "A resposta faz o **caminho inverso**; cada roteador decide de novo, de forma independente.",
        ], "aplicacao")
        self._begin("TCP ACK", "TCP", "pc", ip)
        self._forward("pc", client(["ACK"], cseq + 1 + n, sseq + 1 + m), "TCP: cliente confirma a resposta", [
            f"O cliente confirma os `{m}` bytes recebidos com ack=`{sseq + 1 + m}`. Sem essa confirmação, o servidor "
            "retransmitiria os dados.",
            "O navegador já pode exibir a página.",
        ], "transporte")

        # --- encerramento
        self.phase = FASE_FIN
        self._begin("TCP FIN, ACK", "TCP", "pc", ip)
        self._forward("pc", client(["FIN", "ACK"], cseq + 1 + n, sseq + 1 + m), "TCP: cliente encerra seu lado (FIN)", [
            "O cliente não tem mais nada a enviar e manda um segmento com a flag **FIN**.",
            "Cada sentido da conexão é fechado separadamente, por isso o encerramento usa quatro segmentos.",
        ], "transporte")
        self._begin("TCP ACK", "TCP", target.id, "pc")
        self._forward(target.id, server(["ACK"], sseq + 1 + m, cseq + 2 + n), "TCP: servidor confirma o FIN", [
            f"O servidor confirma o FIN com ack=`{cseq + 2 + n}` (o FIN consome um número de sequência).",
        ], "transporte")
        self._begin("TCP FIN, ACK", "TCP", target.id, "pc")
        self._forward(target.id, server(["FIN", "ACK"], sseq + 1 + m, cseq + 2 + n), "TCP: servidor encerra seu lado (FIN)", [
            "O servidor também terminou e envia o seu **FIN**.",
        ], "transporte")
        self._begin("TCP ACK", "TCP", "pc", ip)
        self._forward("pc", client(["ACK"], cseq + 2 + n, sseq + 2 + m), "TCP: último ACK", [
            f"O cliente confirma o FIN do servidor com ack=`{sseq + 2 + m}`. **Conexão encerrada.**",
        ], "transporte")

        routers = self.ttl - syn.ttl  # cada roteador decrementou o TTL do SYN em 1
        path = (f"Cada pacote passou por {routers} roteadores; o TTL saiu com `{self.ttl}` e chegou com `{self.ttl - routers}`."
                if routers else "Origem e destino estão na mesma rede: nenhum roteador no caminho e o TTL não mudou.")
        return self._finish(True, "Requisição concluída", [
            f"A página de `{name}` foi recebida: {len(self.packets)} pacotes trocados no total.",
            path,
            "Em todo o percurso os **IPs** identificaram origem e destino finais (exceto pela troca do NAT), enquanto "
            "os **MACs** mudaram a cada enlace.",
        ])


def simulate(dest: str, ttl: int = 64) -> dict:
    """Valida a entrada e executa a simulação completa."""
    dest = str(dest or "").strip().lower()
    dest = re.sub(r"^https?://", "", dest).split("/")[0]
    if not dest:
        raise SimulationError("Informe um destino: um nome (www.exemplo.com.br) ou um endereço IPv4.")
    try:
        ttl = int(ttl)
    except (TypeError, ValueError):
        raise SimulationError("O TTL deve ser um número inteiro.") from None
    if not 1 <= ttl <= 255:
        raise SimulationError("O TTL é um campo de 8 bits: use um valor entre 1 e 255.")

    topo = build_topology()
    try:
        addr = ipaddress.IPv4Address(dest)
    except ValueError:
        if not HOSTNAME.match(dest):
            raise SimulationError(f"“{dest}” não é um nome de host nem um endereço IPv4 válido.") from None
    else:
        if addr.is_loopback:
            raise SimulationError("127.0.0.0/8 é loopback: o pacote nunca sai da própria máquina.")
        if addr.is_multicast or addr.is_unspecified or str(addr) == "255.255.255.255":
            raise SimulationError("Use um endereço unicast: multicast, 0.0.0.0 e broadcast não servem para uma conexão TCP.")
        if topo.nodes["pc"].has_ip(str(addr)):
            raise SimulationError("Esse é o IP do próprio computador: o pacote não sairia para a rede.")
    return Simulation(topo, dest, ttl).run()
