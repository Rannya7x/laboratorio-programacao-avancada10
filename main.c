#include <stdio.h>
#include <stdlib.h>
#include "sniff_utils.h"

int main(int argc, char *argv[]) {
    //valida argumentos
    if (argc != 2){
        printf("Uso: %s <arquivo.rawcap>\n", argv[1]);
        return 1;
    }

    //abre arquivo
    FILE *arquivo = fopen(argv[1], "rb");
    if (arquivo == NULL){
        perror("Erro ao abrir o arquivo");
        return 1;
    }

    //chama funcao pra processar as camadas do protocolo
    processar_dados_rede(arquivo);

    fclose(arquivo);

    return 0;
}