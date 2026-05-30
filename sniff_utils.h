#ifndef SNIFF_UTILS_H
#define SNIFF_UTILS_H

#include <stdint.h>
#include <stdio.h>

//camada de enlace ethernet
typedef struct {
    uint8_t daddr[6]; // Endereco MAC de destino
    uint8_t saddr[6]; // Endereco MAC de origem (source)
    uint16_t protocol; // Protocolo da próxima camada (IP!)
} ethernet_hdr_t;

//camada de rede ip
typedef struct {
    uint8_t hdr_len:4, // Tamanho do Cabeçalho,
            version:4; // Versão do IP
    uint8_t tos; // Tipo de serviço
    uint16_t tot_len; // Tamanho total do IP
    uint16_t id; // Id do pacote
    uint16_t frag_off; // Fragmentado?
    uint8_t ttl; // Tempo de vida
    uint8_t protocol; // Protocolo próxima camada (TCP!)
    uint16_t check; // Checksum
    uint8_t saddr[4]; // Endereço IP de origem
    uint8_t daddr[4]; // Endereço IP de destino
} ip_hdr_t;
//camada de transporte tcp
typedef struct {
    uint16_t sport; // Porta TCP de origem
    uint16_t dport; // Porta TCP de destino
    uint32_t seq; // Sequência
    uint32_t ack_seq; // Acknowledgement
    uint8_t reservado:4, // Não usado
            hdr_len:4; // Tamanho do cabecalho
    uint8_t flags; // Flags do TCP
    uint16_t window; // Tamanho da janela
    uint16_t check; // Checksum
    uint16_t urg_ptr; // Urgente
} tcp_hdr_t;

void processar_dados_rede(FILE *arquivo);

#endif 