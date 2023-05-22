# Diagramas de Sistema

### Diagrama de Registo

```mermaid
sequenceDiagram
    participant C as Cliente
    participant S as Servidor
    participant D as Base de Dados

    %% inicialização
    S ->> S: inicia as sockets
    C ->> C: inicia as sockets e as threads
    C ->> S: inicia comunicação
    S ->> S: aloca cada thread ao cliente
    C ->> S: envia pedido de registo
    S ->> C: envia pedido de credenciais (nome de utilizador)

    %% verificação do nome de utilizador
    loop verificação do nome de utilizador
        C ->> S: envia um nome de utilizador
        D ->> D: elimina potenciais nomes de utilizadores temporários
        S ->> D: envia query de pesquisa pelo nome do utilizador
        D ->> D: verifica se o nome de utilizador já existe
        note right of D: o nome de utilizador já existe
        D ->> S: envia a lista de resultados
        S ->> C: responde com um novo pedido de credenciais
        C ->> S: envia um novo nome de utilizador
    end
    note right of D: o nome de utilizador não existe
    D ->> S: envia uma lista vazia de resultados

    %% CHAP
    alt Challenge Handshake Authentication Protocol
        S ->> S: utiliza curvas elíticas para gerar <br> par de chaves Diffie-Hellman
        S ->> D: envia o nome de utilizador e a chave privada
        D ->> D: armazena o nome de utilizador e a chave privada <br> em estatuto temporário
        S ->> C: envia a chave pública do servidor
        S ->> C: envia pedido de credenciais (palavra-passe)
        C ->> C: utiliza curvas elíticas para gerar <br> par de chaves Diffie-Hellman
        C ->> S: envia a chave pública, nome de utilizador, <br> salt, vetor de inicialização, palavra-passe cifrada
        S ->> S: deriva a chave de curva elítica para a decifra
        S ->> S: decifra a palavra-passe cifrada do utilizador
        S ->> D: envia a palavra-passe e a chave privada do utilizador
        D ->> D: armazena o nome de utilizador e a palavra-passe <br> e retira o estatuto temporário do utilizador

    %% ZKP
    else Protocolo de Conhecimento Zero (Schnorr)
        S ->> S: define o parâmetro t <br> calcula números primos P e Q <br> gera o gerador B
        S ->> D: envia o nome de utilizador, P, Q, B e t
        D ->> D: armazena o nome de utilizador, t, P, Q, B <br> em estatuto temporário
        S ->> C: envia Q, P, B
        C ->> C: gera um par de chaves pública e privada
        C ->> S: envia o nome de utilizador e a chave pública
        S ->> D: envia o nome de utilizador e a chave pública do utilizador
        D ->> D: armazena a chave pública do utilizador <br> e retira o estatuto temporário do utilizador
    end
    S ->> C: regista o utilizador
```

- O servidor inicializa três threads: principal, chaves, mensagens. Assim será possível a cada utilizador usar o chat com vários utilizadores simultaneamente.

---

### Diagrama de _Login_

```mermaid
sequenceDiagram
    participant C as Cliente
    participant S as Servidor
    participant D as Base de Dados

    S ->> S: inicia as sockets
    C ->> S: envia pedido de login
    S ->> S: aloca cada thread ao cliente
    S ->> C: responde com o pedido de credenciais (nome de utilizador)

    loop verificação do nome de utilizador
    C ->> S: envia um nome de utilizador
    S ->> D: envia query de pesquisa pelo nome do utilizador
        D ->> D: verifica se o nome de utilizador já existe
        note right of D: o nome de utilizador já existe
        D ->> S: envia a lista de resultados
        S ->> C: responde com um novo pedido de credenciais
        C ->> S: envia um novo nome de utilizador
    end
    note right of D: o nome de utilizador não existe
    D ->> S: envia uma lista vazia de resultados
    S ->> S: guarda o nome de utilizador
    S ->> S: verifica o tipo de login associado (CHAP ou Schnorr)
    S ->> C: responde com o pedido de credenciais (palavra-passe)


    loop verificação da palavra-passe
        alt Challenge Handshake Authentication Protocol
            C ->> S: envia a sua palavra-passe
            S ->> S: gera um Nonce (random 128)
            S ->> D: envia o Nonce gerado
            D ->> D: guarda o nonce
            S ->> C: envia o Nonce
            C ->> C: gera hash da palavra-passe + nonce + pepper
            C ->> C: gera o desafio do CHAP com o nonce e o hash calculado.
            C ->> S: nome de utilizador, desafio
            S ->> D: envia query de pesquisa do nonce e segredo através do username
            D ->> D: executa a query
            D ->> S: retorna segredo e nonce
            S ->> S: calcula o desafio com os dados da BD
            note right of S: desafio diferente == palavra passe incorreta



        else Protocolo de Conhecimento Zero (Schnorr)
            C ->> S: envia a sua palavra-passe
            S ->> D: envia query de pesquisa pelos parâmetros P, Q e B <br> do protocolo baseado com o nome de utilizador.
            D ->> S: envia P,Q e B
            S ->> C: envia P,Q e B
            C ->> C: calcula número aleatório (R)
            C ->> C: com R, B e P calcula e um número <br> para enviar para o servidor (X)
            C ->> S: envia X
            S ->> S: gera número aleatório (E)
            S ->> D: envia nome de utilizador, X, E
            D ->> D: guarda X, E
            S ->> C: envia E
            C ->> C: calcula a resposta (Y) com a chave privada
            C ->> S: envia Y
            S ->> D: envia query de pesquisa pelos parâmetros <br> P,B,E,X e chave pública
            D ->> S: envia P,B,E,X e chave pública
            S ->> S: calcula Z
            note right of S: Z != X significa palavra passe incorreta
        end

        S ->> C: volta a pedir palavra-passe
    end
    note right of D: palavra-passe incorreta
    S ->> C: autenticação com sucesso, apresenta menus


```

- O servidor inicializa três threads: principal, chaves, mensagens. Assim, será possível a cada utilizador usar o chat com vários utilizadores simultaneamente.