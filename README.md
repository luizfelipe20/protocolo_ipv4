# Ciclo de vida de uma requisição TCP/IP (IPv4)

Simulador visual para estudar redes de computadores. Mostra, passo a passo, o que acontece com uma
requisição HTTP desde o seu computador até o servidor e de volta: DNS, ARP, handshake TCP, roteamento
salto a salto, NAT, TTL, checksum e encerramento da conexão.

## Como rodar

Precisa apenas de Python 3.10 ou mais novo. Não há dependências para instalar.

```bash
python3 server.py
```

Abra <http://127.0.0.1:8000> no navegador. Para usar outra porta: `python3 server.py --port 9000`.

## Como usar

- **Destino**: um nome (`www.exemplo.com.br`) ou um endereço IPv4. **TTL inicial**: de 1 a 255.
- **Reproduzir** anima a simulação inteira; as setas avançam um passo por vez.
- A cada passo a tela mostra a camada em ação, a explicação, as tabelas consultadas (rotas, ARP, MAC, NAT)
  e o quadro com seus cabeçalhos. Campos alterados no salto ficam destacados.
- Passe o mouse sobre um campo do cabeçalho para ver o que ele significa.
- Clique em um equipamento do mapa para ver suas interfaces e sua tabela de rotas.

Atalhos: `→` próximo passo · `←` passo anterior · `espaço` reproduzir/pausar · `N` próximo pacote · `Home` início.

## Cenários para explorar

| Destino | TTL | O que observar |
|---|---|---|
| `www.exemplo.com.br` | 64 | Caminho completo: DNS, ARP, NAT, 4 roteadores, HTTP 200 |
| `192.168.0.20` | 64 | Mesma rede: entrega direta, sem gateway e sem mudar o TTL |
| `www.exemplo.com.br` | 1 a 4 | O TTL expira em um roteador diferente a cada valor (princípio do traceroute) |
| `nao-existe.com.br` | 64 | DNS responde NXDOMAIN |
| `8.8.8.8` | 64 | O backbone não tem rota: ICMP Destination Unreachable |
| `203.0.113.130` | 64 | A máquina existe, mas a porta 80 está fechada: TCP RST |
| `192.168.0.99` | 64 | Ninguém responde ao ARP |

## Rede simulada

```
PC ── Switch ── Roteador de casa (NAT) ── Roteador ISP ── Backbone ── Borda do datacenter ── Servidor web
        │                                      │
   Servidor local                         Servidor DNS
```

A rede de casa usa `192.168.0.0/24`. A "Internet" usa as faixas reservadas para documentação
(RFC 5737), que nunca aparecem na Internet real.

## Estrutura

```
server.py              servidor HTTP: arquivos estáticos e a API
netsim/ipv4.py         checksum, cabeçalho IPv4 e cálculo de rede com a máscara
netsim/topology.py     equipamentos, interfaces, rotas e enlaces
netsim/simulation.py   motor da simulação: encaminhamento, ARP, switch, NAT, ICMP, TCP e HTTP
static/                frontend (index.html, style.css, app.js)
```

A simulação é calculada no backend. `POST /api/simulate` recebe `{"destino": "...", "ttl": 64}` e devolve
a topologia, a lista de pacotes e a lista de passos que o frontend anima. Para mudar a rede (novos
roteadores, outras rotas), edite `build_topology()` em `netsim/topology.py`.

## Simplificações

Para manter o foco no caminho do pacote, a simulação não inclui fragmentação, perda e retransmissão,
controle de congestionamento, opções TCP, TLS/HTTPS nem IPv6. Os números de sequência começam em valores
fixos (1000 e 5000); na prática são aleatórios.
