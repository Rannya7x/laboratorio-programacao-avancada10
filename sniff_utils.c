#include "sniff_utils.h"
#include <arpa/inet.h>
#include <stdio.h>
void processar_dados_rede(FILE *arquivo){
    //ethernet
    ethernet_hdr_t eth;
    fread(&eth, sizeof(ethernet_hdr_t), 1, arquivo);
    printf("Lendo Ethernet ..\n");

    //endereços mac lidos em hexadecimal, 6 bytes cada
    printf("\t--> MAC de Origem:  %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n", 
            eth.saddr[0], eth.saddr[1], eth.saddr[2], eth.saddr[3], eth.saddr[4], eth.saddr[5]);
    printf("\t--> MAC de Destino: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n", 
            eth.daddr[0], eth.daddr[1], eth.daddr[2], eth.daddr[3], eth.daddr[4], eth.daddr[5]);

    //ip
    ip_hdr_t ip;
    fread(&ip, sizeof(ip_hdr_t), 1, arquivo); 
    printf("Lendo IP ..\n");
    printf("\t--> Versão do IP: %d\n", ip.version);
    //tamanho do cabeçalho é dado em múltiplos de 32 bits (4 bytes)
    printf("\t--> Tamanho do cabeçalho: %d bytes\n", ip.hdr_len * 4);

    //converte tamanho do pacote network byte order para Local
    printf("\t--> Tamanho do pacote: %d bytes\n", ntohs(ip.tot_len));
    printf("\t--> Endereço IP de Origem:  %d.%d.%d.%d\n", ip.saddr[0], ip.saddr[1], ip.saddr[2], ip.saddr[3]);
    printf("\t--> Endereço IP de Destino: %d.%d.%d.%d\n", ip.daddr[0], ip.daddr[1], ip.daddr[2], ip.daddr[3]);

    //pula opções variáveis do ip
    fseek(arquivo, ip.hdr_len * 4 - sizeof(ip_hdr_t), SEEK_CUR);

    //tcp
    tcp_hdr_t tcp;
    fread(&tcp, sizeof(tcp_hdr_t), 1, arquivo);
    printf("Lendo TCP ..\n");

    //converte portas
    printf("\t--> Porta de Origem:  %d\n", ntohs(tcp.sport));
    printf("\t--> Porta de Destino: %d\n", ntohs(tcp.dport));
    printf("\t--> Tamanho do cabeçalho: %d bytes\n", tcp.hdr_len * 4);

    //pula variaveis tcp
    fseek(arquivo, tcp.hdr_len * 4 - sizeof(tcp_hdr_t), SEEK_CUR);

    //dados http
    int tam_dados = ntohs(ip.tot_len) - (ip.hdr_len * 4) - (tcp.hdr_len * 4);
    printf("Lendo Dados HTTP ..\n");
    printf("\t--> Tamanho dos dados: %d bytes\n", tam_dados);
    printf("\t--> Dados: \n");
    for(int i = 0; i < tam_dados; i++){
        printf("%c", fgetc(arquivo)); //imprime byte a byte como caractere
    }
    printf("\n");

}