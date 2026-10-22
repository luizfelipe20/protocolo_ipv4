"""Utilitários IPv4: checksum, montagem do cabeçalho e cálculo de rede."""

from __future__ import annotations

import ipaddress
import struct

PROTOCOLS = {1: "ICMP", 6: "TCP", 17: "UDP"}


def checksum(data: bytes) -> int:
    """Checksum da Internet (RFC 1071): complemento de um da soma de palavras de 16 bits."""
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def build_header(src: str, dst: str, proto: int, ttl: int, total_length: int, ident: int) -> bytes:
    """Monta os 20 bytes do cabeçalho IPv4 (sem opções, flag DF ligada) com o checksum preenchido."""
    head = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,  # versão 4, IHL 5 (5 x 4 = 20 bytes)
        0,  # DSCP/ECN
        total_length,
        ident,
        0x4000,  # flags: DF, deslocamento de fragmento 0
        ttl,
        proto,
        0,  # checksum zerado para o cálculo
        ipaddress.IPv4Address(src).packed,
        ipaddress.IPv4Address(dst).packed,
    )
    return head[:10] + struct.pack("!H", checksum(head)) + head[12:]


def to_binary(ip: str) -> str:
    return ".".join(f"{octet:08b}" for octet in ipaddress.IPv4Address(ip).packed)


def and_calc(dst: str, own_ip: str, prefix: int) -> dict:
    """AND bit a bit entre o destino e a máscara, comparado com a rede do próprio host."""
    own = ipaddress.ip_interface(f"{own_ip}/{prefix}").network
    mask = str(own.netmask)
    result = ipaddress.ip_interface(f"{dst}/{prefix}").network.network_address
    return {
        "dst": dst,
        "mask": mask,
        "prefix": prefix,
        "result": str(result),
        "own_network": str(own.network_address),
        "same": result == own.network_address,
        "dst_bin": to_binary(dst),
        "mask_bin": to_binary(mask),
        "result_bin": to_binary(str(result)),
    }
