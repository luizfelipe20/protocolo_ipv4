"use strict";

const $ = (sel) => document.querySelector(sel);
const SVG_NS = "http://www.w3.org/2000/svg";
const REDUCED_MOTION = matchMedia("(prefers-reduced-motion: reduce)").matches;

const state = { data: null, idx: 0, playing: false, speed: 1, run: 0, timer: null, nodes: {}, links: {} };

const PRESETS = [
  { label: "Site remoto", destino: "www.exemplo.com.br", ttl: 64 },
  { label: "Servidor na mesma rede", destino: "192.168.0.20", ttl: 64 },
  { label: "TTL = 3 (expira no caminho)", destino: "www.exemplo.com.br", ttl: 3 },
  { label: "Nome inexistente", destino: "nao-existe.com.br", ttl: 64 },
  { label: "Rede sem rota", destino: "8.8.8.8", ttl: 64 },
  { label: "Porta fechada", destino: "203.0.113.130", ttl: 64 },
  { label: "Host que não responde", destino: "192.168.0.99", ttl: 64 },
];

const LAYER_NAMES = { aplicacao: "Aplicação", transporte: "Transporte", rede: "Rede", enlace: "Enlace", fisica: "Física" };

// Descrição de cada campo, exibida ao passar o mouse.
const GLOSS = {
  "eth.dst": "MAC de destino: quem deve receber o quadro NESTE enlace (o próximo salto, não o destino final).",
  "eth.src": "MAC de origem: a interface que transmitiu o quadro neste enlace.",
  "eth.type": "EtherType: qual protocolo vem dentro do quadro (0x0800 = IPv4, 0x0806 = ARP).",
  "ip.version": "Versão do protocolo IP: 4.",
  "ip.ihl": "Tamanho do cabeçalho em palavras de 32 bits. 5 = 20 bytes, sem opções.",
  "ip.total_length": "Tamanho total do pacote em bytes: cabeçalho IP + dados.",
  "ip.identification": "Identifica o pacote; serve para remontar fragmentos.",
  "ip.flags": "DF (Don't Fragment): os roteadores não podem fragmentar este pacote.",
  "ip.ttl": "Time To Live: cada roteador subtrai 1. Ao chegar a 0, o pacote é descartado. Evita loops infinitos.",
  "ip.protocol": "Protocolo da camada de transporte que vem a seguir: 1 = ICMP, 6 = TCP, 17 = UDP.",
  "ip.checksum": "Soma de verificação só do cabeçalho IP. Recalculada em todo roteador, porque o TTL muda.",
  "ip.src": "Endereço IPv4 de origem. Só muda no caminho se houver NAT.",
  "ip.dst": "Endereço IPv4 do destino final. Permanece o mesmo de ponta a ponta (exceto no NAT reverso).",
  "l4.sport": "Porta de origem: identifica o processo que enviou os dados.",
  "l4.dport": "Porta de destino: identifica o serviço (80 = HTTP, 53 = DNS).",
  "l4.seq": "Número de sequência: posição do primeiro byte deste segmento no fluxo de dados.",
  "l4.ack": "Número de confirmação: o próximo byte que este lado espera receber.",
  "l4.flags": "Flags de controle: SYN abre, ACK confirma, PSH entrega dados, FIN encerra, RST aborta.",
  "l4.window": "Janela: quantos bytes este lado ainda aceita receber (controle de fluxo).",
  "l4.type": "Tipo da mensagem ICMP: 3 = destino inalcançável, 11 = tempo excedido.",
  "l4.code": "Código: detalha o motivo dentro do tipo ICMP.",
  "l4.embedded": "Cópia do cabeçalho do pacote que causou o erro, para a origem identificar a conexão afetada.",
  "arp.op": "Operação: 1 = pergunta (request), 2 = resposta (reply).",
  "arp.sha": "MAC de quem envia a mensagem ARP.",
  "arp.spa": "IP de quem envia a mensagem ARP.",
  "arp.tha": "MAC procurado. Vai zerado na pergunta, pois ainda é desconhecido.",
  "arp.tpa": "IP cujo MAC se quer descobrir.",
};

const esc = (v) => String(v).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const fmt = (text) => esc(text).replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>").replace(/`(.+?)`/g, "<code>$1</code>");
const nodeName = (id) => (state.nodes[id] ? state.nodes[id].name : id);

function svg(tag, attrs = {}, text) {
  const el = document.createElementNS(SVG_NS, tag);
  for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, v);
  if (text !== undefined) el.textContent = text;
  return el;
}

// ---------------------------------------------------------------- mapa da rede

function drawTopology(topo) {
  const root = $("#svg");
  root.replaceChildren();
  root.setAttribute("viewBox", `0 0 ${topo.width} ${topo.height}`);
  state.nodes = Object.fromEntries(topo.nodes.map((n) => [n.id, n]));
  state.links = {};

  for (const z of topo.zones) {
    const g = svg("g", { class: "zone" });
    g.append(svg("rect", { x: z.x, y: z.y, width: z.w, height: z.h, rx: 14 }), svg("text", { x: z.x + 12, y: z.y + z.h - 10 }, z.label));
    root.append(g);
  }

  const labelled = new Set();
  for (const link of topo.links) {
    const a = state.nodes[link.a], b = state.nodes[link.b];
    const line = svg("line", { class: "link", x1: a.x, y1: a.y, x2: b.x, y2: b.y });
    state.links[`${a.id}|${b.id}`] = state.links[`${b.id}|${a.id}`] = line;
    root.append(line);
    if (labelled.has(link.network)) continue;
    labelled.add(link.network);
    const mx = (a.x + b.x) / 2, my = (a.y + b.y) / 2;
    const horizontal = a.y === b.y;
    root.append(svg("text", { class: "net", x: horizontal ? mx : mx + 8, y: horizontal ? my - 8 : my, "text-anchor": horizontal ? "middle" : "start" }, link.network));
  }

  for (const n of topo.nodes) {
    const g = svg("g", { class: `node kind-${n.kind}`, transform: `translate(${n.x},${n.y})`, tabindex: 0, role: "button", "aria-label": `${n.name}: ver detalhes` });
    const shape = n.kind === "router" ? svg("circle", { r: 24 })
      : n.kind === "switch" ? svg("rect", { x: -28, y: -15, width: 56, height: 30, rx: 6 })
      : svg("rect", { x: -27, y: -20, width: 54, height: 40, rx: 8 });
    shape.classList.add("shape");
    g.append(shape, svg("text", { class: "short" }, n.short));
    const right = n.label === "right";
    const lx = right ? 36 : 0, ly = right ? -4 : n.label === "above" ? -24 : 44, anchor = right ? "start" : "middle";
    g.append(svg("text", { class: "name", x: lx, y: ly, "text-anchor": anchor }, n.name));
    n.interfaces.forEach((iface, i) => {
      g.append(svg("text", { class: "ip", x: lx, y: ly + 13 + i * 12, "text-anchor": anchor }, `${iface.ip}/${iface.prefix}`));
    });
    g.addEventListener("click", () => openNode(n));
    g.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); e.stopPropagation(); openNode(n); } });
    n.el = g;
    root.append(g);
  }
  root.append(svg("g", { id: "pkts" }));
}

function tableHtml(title, columns, rows, highlight) {
  const body = rows.length
    ? rows.map((r, i) => `<tr class="${i === highlight ? "hl" : ""}">${r.map((c) => `<td>${esc(c)}</td>`).join("")}</tr>`).join("")
    : `<tr><td class="empty" colspan="${columns.length}">vazia</td></tr>`;
  return `<div class="tbl"><table><caption>${esc(title)}</caption><thead><tr>${columns.map((c) => `<th>${esc(c)}</th>`).join("")}</tr></thead><tbody>${body}</tbody></table></div>`;
}

function openNode(n) {
  let html = `<h3>${esc(n.name)}</h3><p>${esc(n.about)}</p>`;
  if (n.interfaces.length) {
    html += tableHtml("Interfaces", ["Interface", "Endereço IPv4", "Rede", "Endereço MAC"],
      n.interfaces.map((i) => [i.name, `${i.ip}/${i.prefix}`, i.network, i.mac]));
    html += tableHtml("Tabela de rotas", ["Destino", "Próximo salto", "Interface"],
      n.routes.map((r) => [r.network, r.via || "diretamente conectada", r.iface]));
  }
  if (n.nat) html += `<p class="note" style="margin-top:12px">Faz NAT na interface <code>${esc(n.nat)}</code>.</p>`;
  $("#dialog-body").innerHTML = html;
  $("#dialog").showModal();
}

function marker(tag, pos, ghost = false) {
  const g = svg("g", { class: `pkt${ghost ? " ghost" : ""}`, transform: `translate(${pos.x},${pos.y})` });
  g.append(svg("circle", { r: 12, class: `tag-${tag}` }), svg("text", { "font-size": tag.length > 3 ? 7 : 8 }, tag));
  $("#pkts").append(g);
  return g;
}

function glide(el, from, to, duration, run) {
  const start = performance.now();
  const step = (now) => {
    if (run !== state.run) return;
    const t = Math.min(1, (now - start) / duration);
    const e = t < 0.5 ? 2 * t * t : 1 - (-2 * t + 2) ** 2 / 2;
    el.setAttribute("transform", `translate(${from.x + (to.x - from.x) * e},${from.y + (to.y - from.y) * e})`);
    if (t < 1) requestAnimationFrame(step);
  };
  requestAnimationFrame(step);
}

// ---------------------------------------------------------------- painéis

function renderTimeline() {
  const box = $("#timeline");
  box.replaceChildren();
  let phase = null;
  state.data.packets.forEach((p, i) => {
    if (p.phase !== phase) {
      phase = p.phase;
      const h = document.createElement("div");
      h.className = "phase";
      h.textContent = phase;
      box.append(h);
    }
    const b = document.createElement("button");
    b.type = "button";
    b.className = "pk";
    b.dataset.packet = i;
    b.innerHTML = `<span class="badge tag-${p.tag}">${p.tag}</span><b>${esc(p.label)}</b><small>${esc(nodeName(p.src))} → ${esc(nodeName(p.dst))}</small>`;
    b.addEventListener("click", () => { setPlaying(false); show(p.first); });
    box.append(b);
  });
}

function renderCalc(c) {
  const row = (label, ip, bin, extra = "") => `${label.padEnd(9)}${ip.padEnd(16)}${bin}${extra}`;
  const verdict = c.same ? "mesma rede → entrega direta" : "redes diferentes → usa o gateway padrão";
  return `<div class="calc"><div class="calc-title">Mesma rede ou outra? AND bit a bit com a máscara</div><pre>${esc(
    [row("Destino", c.dst, c.dst_bin), row("Máscara", c.mask, c.mask_bin, `  (/${c.prefix})`)].join("\n"))}\n<span class="res">${esc(
    row("AND", c.result, c.result_bin))}</span>\n${esc(`Rede deste host: ${c.own_network} → ${verdict}`)}</pre></div>`;
}

function renderExplain(ev, pk) {
  const where = ev.kind === "node" ? nodeName(ev.node) : `${nodeName(ev.from)} → ${ev.also.length ? "todos no enlace" : nodeName(ev.to)}`;
  const status = ev.status === "ok" ? '<span class="status ok">✓ sucesso</span>' : ev.status === "drop" ? '<span class="status drop">✕ falha</span>' : "";
  $("#explain").innerHTML =
    `<div class="where"><span class="badge tag-${pk.tag}">${pk.tag}</span> ${esc(pk.label)} · ${esc(where)} ${status}</div>` +
    `<h3>${esc(ev.title)}</h3><ul>${ev.details.map((d) => `<li>${fmt(d)}</li>`).join("")}</ul>` +
    (ev.calc ? renderCalc(ev.calc) : "") +
    ev.tables.map((t) => tableHtml(t.title, t.columns, t.rows, t.highlight)).join("");
  for (const li of $("#layers").children) {
    const on = li.dataset.layer === ev.layer;
    li.classList.toggle("on", on);
    if (on) li.setAttribute("aria-current", "true"); else li.removeAttribute("aria-current");
  }
}

function renderFrame(ev) {
  const f = ev.frame;
  if (!f) {
    $("#frame").innerHTML = '<p class="note">Nenhum quadro em trânsito neste passo.</p>';
    return;
  }
  const field = (key, label, value) =>
    `<div class="f${ev.changes.includes(key) ? " chg" : ""}" title="${esc(GLOSS[key] || "")}"><span>${esc(label)}</span><b>${esc(value)}</b></div>`;
  const box = (cls, title, sub, inner) =>
    `<div class="box ${cls}"><div class="box-title">${esc(title)}<span>${esc(sub)}</span></div>${inner}</div>`;

  let inner = "";
  if (f.arp) {
    const a = f.arp;
    inner = box("ip", "ARP", "resolução IP → MAC", `<div class="fields">${field("arp.op", "Operação", a.op)}${field("arp.sha", "MAC do remetente", a.sha)}${field("arp.spa", "IP do remetente", a.spa)}${field("arp.tha", "MAC procurado", a.tha)}${field("arp.tpa", "IP procurado", a.tpa)}</div>`);
  } else {
    const ip = f.ip, l4 = f.l4;
    let payload = "";
    if (f.payload) payload = box("app", f.payload.kind, `${f.payload.length} bytes · camada de aplicação`, `<pre class="payload">${esc(f.payload.text)}</pre>`);
    let l4html;
    if (l4.kind === "TCP") {
      l4html = box("l4", "TCP", "segmento · camada de transporte · 20 bytes",
        `<div class="fields">${field("l4.sport", "Porta origem", l4.sport)}${field("l4.dport", "Porta destino", l4.dport)}${field("l4.seq", "Seq", l4.seq)}${field("l4.ack", "Ack", l4.ack)}${field("l4.flags", "Flags", l4.flags.join(", "))}${field("l4.window", "Janela", l4.window)}</div>${payload}`);
    } else if (l4.kind === "UDP") {
      l4html = box("l4", "UDP", "datagrama · camada de transporte · 8 bytes",
        `<div class="fields">${field("l4.sport", "Porta origem", l4.sport)}${field("l4.dport", "Porta destino", l4.dport)}</div>${payload}`);
    } else {
      const e = l4.embedded;
      const ports = e.sport ? [`:${e.sport}`, `:${e.dport}`] : ["", ""];
      l4html = box("l4", "ICMP", "mensagem de controle · 8 bytes",
        `<div class="fields">${field("l4.type", "Tipo", l4.type)}${field("l4.code", "Código", l4.code)}${field("", "Significado", l4.desc)}${field("l4.embedded", "Pacote original", `${e.proto} ${e.src}${ports[0]} → ${e.dst}${ports[1]}`)}</div>${payload}`);
    }
    inner = box("ip", "IPv4", "pacote · camada de rede · 20 bytes",
      `<div class="fields">${field("ip.version", "Versão", ip.version)}${field("ip.ihl", "IHL", ip.ihl)}${field("ip.total_length", "Tamanho total", ip.total_length)}${field("ip.identification", "Identificação", ip.identification)}${field("ip.flags", "Flags", ip.flags)}${field("ip.ttl", "TTL", ip.ttl)}${field("ip.protocol", "Protocolo", ip.protocol)}${field("ip.checksum", "Checksum", ip.checksum)}${field("ip.src", "IP origem", ip.src)}${field("ip.dst", "IP destino", ip.dst)}</div><p class="hex" title="Os 20 bytes do cabeçalho IPv4 em hexadecimal">${esc(ip.hex)}</p>${l4html}`);
  }

  let html;
  if (f.eth) {
    html = box("eth", "Ethernet II", "quadro · camada de enlace",
      `<div class="fields">${field("eth.dst", "MAC destino", f.eth.dst)}${field("eth.src", "MAC origem", f.eth.src)}${field("eth.type", "EtherType", f.eth.type)}</div>${inner}`);
  } else {
    html = '<p class="note">Ainda sem cabeçalho Ethernet: falta descobrir o MAC do próximo salto.</p>' + inner;
  }
  if (ev.changes.length) html += '<p class="chg-note"><i></i>Campos alterados neste salto. Passe o mouse sobre um campo para ver o que ele significa.</p>';
  $("#frame").innerHTML = html;
}

// ---------------------------------------------------------------- reprodução

function show(i, animate = true) {
  const { events, packets } = state.data;
  state.idx = Math.max(0, Math.min(events.length - 1, i));
  const run = ++state.run;
  clearTimeout(state.timer);
  const ev = events[state.idx], pk = packets[ev.packet];

  for (const n of Object.values(state.nodes)) n.el.classList.remove("on", "ok", "drop");
  for (const l of Object.values(state.links)) l.classList.remove("on");
  $("#pkts").replaceChildren();

  let duration;
  if (ev.kind === "node") {
    const n = state.nodes[ev.node];
    n.el.classList.add("on");
    if (ev.status !== "info") n.el.classList.add(ev.status);
    if (ev.frame) marker(pk.tag, { x: n.x - 24, y: n.y - 26 });
    duration = 2800;
  } else {
    const from = state.nodes[ev.from];
    const move = 900 / state.speed;
    [ev.to, ...ev.also].forEach((id, k) => {
      const to = state.nodes[id];
      state.links[`${ev.from}|${id}`]?.classList.add("on");
      const m = marker(pk.tag, animate && !REDUCED_MOTION ? from : to, k > 0);
      if (animate && !REDUCED_MOTION) glide(m, from, to, move, run);
    });
    duration = 1500;
  }

  renderExplain(ev, pk);
  renderFrame(ev);

  const list = $("#timeline");
  for (const b of list.querySelectorAll(".pk")) {
    const on = Number(b.dataset.packet) === ev.packet;
    b.classList.toggle("on", on);
    if (on) {
      const top = b.offsetTop - list.offsetTop;
      if (top < list.scrollTop || top + b.offsetHeight > list.scrollTop + list.clientHeight) list.scrollTop = top - 40;
    }
  }
  $("#scrub").value = state.idx;
  $("#counter").textContent = `Passo ${state.idx + 1} de ${events.length}`;
  $("#first").disabled = $("#prev").disabled = state.idx === 0;
  $("#next").disabled = $("#nextpkt").disabled = state.idx === events.length - 1;

  if (state.playing) {
    state.timer = setTimeout(() => {
      if (state.idx >= events.length - 1) setPlaying(false);
      else show(state.idx + 1);
    }, duration / state.speed);
  }
}

function setPlaying(on) {
  state.playing = on;
  clearTimeout(state.timer);
  $("#play").textContent = on ? "⏸ Pausar" : "▶ Reproduzir";
  if (!on || !state.data) return;
  const last = state.data.events.length - 1;
  show(state.idx >= last ? 0 : state.idx + 1);
}

function nextPacket() {
  const { events } = state.data;
  const current = events[state.idx].packet;
  const i = events.findIndex((e, k) => k > state.idx && e.packet !== current);
  show(i === -1 ? events.length - 1 : i);
}

// ---------------------------------------------------------------- entrada

async function simulate() {
  const destino = $("#destino").value.trim();
  const ttl = Number($("#ttl").value);
  const erro = $("#erro");
  setPlaying(false);
  let data;
  try {
    const res = await fetch("/api/simulate", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ destino, ttl }) });
    data = await res.json();
    if (!res.ok) throw new Error(data.erro || "Não foi possível simular.");
  } catch (err) {
    erro.textContent = err instanceof TypeError ? "Sem conexão com o backend. O server.py está em execução?" : err.message;
    erro.hidden = false;
    return;
  }
  erro.hidden = true;
  for (const b of $("#presets").children) b.classList.toggle("on", b.dataset.destino === destino && Number(b.dataset.ttl) === ttl);
  state.data = data;
  drawTopology(data.topology);
  renderTimeline();
  $("#scrub").max = data.events.length - 1;
  show(0, false);
}

for (const p of PRESETS) {
  const b = document.createElement("button");
  b.type = "button";
  b.textContent = p.label;
  b.dataset.destino = p.destino;
  b.dataset.ttl = p.ttl;
  b.addEventListener("click", () => { $("#destino").value = p.destino; $("#ttl").value = p.ttl; simulate(); });
  $("#presets").append(b);
}

$("#form").addEventListener("submit", (e) => { e.preventDefault(); simulate(); });
$("#play").addEventListener("click", () => setPlaying(!state.playing));
$("#first").addEventListener("click", () => { setPlaying(false); show(0, false); });
$("#prev").addEventListener("click", () => { setPlaying(false); show(state.idx - 1, false); });
$("#next").addEventListener("click", () => { setPlaying(false); show(state.idx + 1); });
$("#nextpkt").addEventListener("click", () => { setPlaying(false); nextPacket(); });
$("#scrub").addEventListener("input", (e) => { setPlaying(false); show(Number(e.target.value), false); });
$("#speed").addEventListener("change", (e) => { state.speed = Number(e.target.value); });

document.addEventListener("keydown", (e) => {
  if (!state.data || $("#dialog").open || e.target.closest("input, select, button, [role=button]")) return;
  const actions = {
    ArrowRight: () => { setPlaying(false); show(state.idx + 1); },
    ArrowLeft: () => { setPlaying(false); show(state.idx - 1, false); },
    " ": () => setPlaying(!state.playing),
    Home: () => { setPlaying(false); show(0, false); },
    n: () => { setPlaying(false); nextPacket(); },
    N: () => { setPlaying(false); nextPacket(); },
  };
  if (actions[e.key]) { e.preventDefault(); actions[e.key](); }
});

simulate();
