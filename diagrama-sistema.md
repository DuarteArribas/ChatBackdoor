# Diagramas de Sistema

### Diagrama de Registo

```mermaid
sequenceDiagram
    participant C as Cliente
    participant S as Servidor
    participant D as Base de Dados
    C ->> C: vê menu de registo
    C ->> C: escolhe método de registo (CHAP / Schnorr)
    
    C ->> S: envia pedido de registo
    S ->> C: envia pedido de credenciais (nome de utilizador)

    %% Verificação do nome de utilizador
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
        S ->> S: gera valor secreto (dA) e ponto público (X) pelo protocolo <br> Diffie-Hellman sobre curvas elíticas (X = G * dA)
        S ->> D: envia o nome de utilizador e o valor secreto (dA)
        D ->> D: armazena o nome de utilizador e o valor secreto (dA) <br> em estatuto temporário
        S ->> C: envia o ponto público (X) do servidor
        S ->> C: envia pedido de credenciais (palavra-passe)
        C ->> C: gera valor secreto (dB) e ponto público (Y) pelo protocolo <br> Diffie-Hellman sobre curvas elíticas (Y = G * dB)
        C ->> C: constrói o ponto chave K(x1,y1) = dB * X <br> e retira a coordenada x1 para a chave k1
        C ->> C: gera salt e vetor de inicialização (iv)
        C ->> C: deriva uma chave por KDF (PBKDF2) <br> através de k1 e do salt
        C ->> C: cifra a palavra-passe com a <br> chave derivada e o iv em AES-CBC <br> (dando padding à palavra-passe)
        C ->> S: envia o ponto público Y, nome de utilizador, <br> salt, vetor de inicialização (iv), palavra-passe cifrada
        S ->> D: envia query de pedido do valor secreto (dA)
        D ->> S: envia resultado da query
        S ->> S: constrói o ponto chave K2(x2,y2) = dA * Y <br> e retira a coordenada x2 para a chave k2, onde k1 = k2
        S ->> S: deriva uma chave por KDF (PBKDF2) <br> através de k2 e do salt
        S ->> S: decifra a palavra-passe cifrada do utilizador <br> através da chave derivada e iv em AES-CBC <br> (tirando o padding ao resultado) 
        S ->> S: gera um novo salt
        S ->> S: calcula o hash (scrypt) da palavra-passe <br> com salt e pepper (hardcoded) concatenados
        S ->> D: envia o nome de utilizador <br> e o hash da palavra passe do utilizador
        D ->> D: atualiza a palavra-passe do utilizador <br> e retira o estatuto temporário do utilizador

    %% ZKP
    else Protocolo de Conhecimento Zero (Schnorr)
        S ->> S: define o parâmetro t \<br> calcula números primos Q e P <br> Q: Q > 2 ** 2t, P: (P - 1) % Q = 0 \<br> gera o gerador β: β = ((α ** ((P - 1) / Q)) % P) 
        note right of S: o gerador β é gerado com base <br> num gerador α aleatório <br> de um conjunto de geradores de P
        S ->> D: envia o nome de utilizador, P, Q, β e t
        D ->> D: armazena o nome de utilizador, t, P, Q, β <br> em estatuto temporário
        S ->> C: envia Q, P, β, t
        C ->> C: gera uma chave privada com Q <br> (a: 0 <= a <= Q - 1)
        C ->> C: gera uma chave pública com P, β e a <br> (v: β ** -a % P)
        C ->> S: envia o nome de utilizador e a chave pública v
        S ->> D: envia o nome de utilizador e a chave pública v do utilizador
        D ->> D: armazena a chave pública do utilizador v <br> e retira o estatuto temporário do utilizador
    end
    S ->> C: envia mensagem de sucesso
```

- O servidor inicializa três threads: principal, chaves, mensagens. Assim será possível a cada utilizador usar o chat com vários utilizadores simultaneamente.

---

### Diagrama de _Login_

```mermaid
sequenceDiagram
    participant C as Cliente
    participant S as Servidor
    participant D as Base de Dados

    C ->> C: vê menu de login
    C ->> C: escolhe método de login (CHAP / Schnorr)
    C ->> S: incia socket principal \ <br> envia pedido de login
    S ->> C: envia pedido de credenciais (nome de utilizador)

    loop Verificação do nome de utilizador
        C ->> S: envia um nome de utilizador
        S ->> D: envia query de pesquisa pelo nome do utilizador
        D ->> D: verifica se o nome de utilizador já existe
        note right of D: o nome de utilizador não existe
        D ->> S: envia uma lista vazia de resultados
        S ->> C: responde com um novo pedido de credenciais
        C ->> S: envia um novo nome de utilizador
    end

    note right of D: o nome de utilizador já existe
    D ->> S: envia a lista de resultados
    S ->> S: guarda o nome de utilizador
    S ->> S: verifica o tipo de login associado (CHAP / Schnorr)

    alt Challenge Handshake Authentication Protocol
        loop Verificação da palavra-passe
            S ->> S: gera um nonce (número aleatório de 128 bits)
            S ->> D: envia o nome de utilizador e o nonce
            D ->> D: armazena o nonce para o utilizador
            S ->> C: envia o nonce
            S ->> C: envia pedido de credenciais (palavra-passe)
            C ->> S: envia a sua palavra-passe
            C ->> C: gera hash da palavra-passe + nonce + pepper
            C ->> C: gera o desafio do CHAP com o nonce e o hash calculado
            C ->> S: envia nome de utilizador e desafio
            S ->> D: envia pedido de recuperar o salt
            S ->> D: envia query de pesquisa do nonce e segredo através do username
            D ->> D: executa a query
            D ->> S: retorna segredo e nonce
            S ->> S: calcula o desafio com os dados da BD
            note right of S: desafio diferente == palavra passe incorreta
            S ->> C: envia novo pedido de credenciais (palavra-passe)
        end

    else Protocolo de Conhecimento Zero (Schnorr)
        loop Verificação do nome de utilizador
            C ->> S: envia o nome do utilizador
            S ->> D: envia query de pesquisa pelos parâmetros <br> P, Q (números primos) e B (gerador) <br> do protocolo baseado no nome de utilizador
            D ->> D: executa a query
            D ->> S: retorna P,Q e B
            S ->> C: envia P,Q e B
            C ->> C: gera número aleatório (r)
            C ->> C: com r, B e P calcula um número (x) <br> para enviar para o servidor
            C ->> S: envia nome de utilizador e x
            S ->> D: envia query para obtenção do parâmetro t
            D ->> D: executa a query
            D ->> S: retorna parâmetro t
            S ->> S: gera número aleatório (e)
            S ->> D: envia nome de utilizador, x, e
            D ->> D: guarda x, e para o nome de utilizador
            S ->> C: envia e
            C ->> C: busca a chave privada (armazenada localmente)
            C ->> C: calcula a resposta (Y) com a chave privada, e, r e Q
            C ->> S: envia y
            S ->> D: envia query de pesquisa pelos parâmetros <br> P,B,e,x e chave pública do cliente
            D ->> D: executa query
            D ->> S: retorna P,B,e,x e chave pública do cliente
            S ->> S: calcula z
            note right of S: z != x significa que cliente não é quem diz ser <br> (não sabe de facto a chave privada)
            S ->> C: envia novo pedido de credenciais (nome de utilizador)
        end
    end
    
    S ->> C: envia mensagem de sucesso
```

- O servidor inicializa três threads: principal, chaves, mensagens. Assim, será possível a cada utilizador usar o chat com vários utilizadores simultaneamente.

### Diagrama de Troca de Mensagens

```mermaid
sequenceDiagram
    participant C1 as Cliente 1
    participant S as Servidor
    participant C2 as Cliente 2
    participant D as Base de Dados

    C1 ->> S: seleciona amigo para conversar
    %% C2 ->> S: seleciona amigo para conversar ->> Acho que isto não é bem assim, CONFIRMAR
    
    %% onde ao certo se está a fazer a verificação de o user2 estar online?

    %% AESCipher Keys
    note right of C1: Troca de chaves de cifra AES
    C1 ->> C1: gera valor secreto (dA) e ponto público (X) pelo protocolo <br> Diffie-Hellman sobre curvas elíticas (X = G * dA)
    C1 ->> S: envia nome de utilizador (próprio), nome de utilizador (amigo) <br>, ponto público X, tipo de chave (AES)
    S ->> S: verifica se o segundo utilizador está online (pelo nome de utilizador)
    note right of S: o segundo utilizador não está online
    S ->> C1: envia mensagem de aviso
    note right of S: o segundo utilizador está online
    S ->> C1: NÃO ESTOU A COMPREENDER. keyExchangeHandler, linha 79
    S ->> C1: envia ponto público Y
    C1 ->> C1: constrói o ponto chave K(x1, y1) = dA * Y <br> e retira a coordenada x1 para a chave k1
    C1 ->> C1: armazena localmente a coordenada x1
    
    %% HMAC Keys
    note right of C1: Troca de chave de integridade de HMAC
    C1 ->> C1: gera valor secreto (dA) e ponto público (X) pelo protocolo <br> Diffie-Hellman sobre curvas elíticas (X = G * dA)
    C1 ->> S: envia nome de utilizador (próprio), nome de utilizador (amigo) <br>, ponto público X, tipo de chave (AES)
    S ->> S: verifica se o segundo utilizador está online (pelo nome de utilizador)
    note right of S: o segundo utilizador não está online
    S ->> C1: envia mensagem de aviso
    note right of S: o segundo utilizador está online
    S ->> C1: NÃO ESTOU A COMPREENDER. keyExchangeHandler, linha 79
    S ->> C1: envia ponto público Y
    C1 ->> C1: constrói o ponto chave K(x1, y1) = dA * Y <br> e retira a coordenada x1 para a chave k1
    C1 ->> C1: armazena localmente a coordenada x1

    %% Assinatura digital RSA
    note right of C1: Geração de chave de assinatura digital (RSA)
    C1 ->> C1: gera números primos p e q
    C1 ->> C1: calcula φN = (p - 1) * (q - 1)
    C1 ->> C1: declara e = 65537
    C1 ->> C1: calcular d = e ** φN
    C1 ->> C1: calcula N = p * q
    C1 ->> C1: armazena localmente p, q, e, d, n
    
    S ->> D: envia pesquisa por mensagens antigas
    D ->> S: envia mensagens antigas
    S ->> C1: mostra mensagens antigas

    loop Troca de mensagens
        C1 ->> C1: escreve uma mensagem
        C1 ->> C1: busca a chave de cifra AES, <br> a chave de integridade HMAC <br> e parâmetros de assinatura digital RSA <br> (p, q, e, d, n, armazenados localmente)
        C1 ->> C1: cifra as chaves de cifra e de HMAC (KEY para simplificação)
        C1 ->> C1: cifra o vetor de inicialização (iv) com <br> KEY e ivKey (parâmetro do sistema)
        C1 ->> C1: cifra a mensagem com a chave de cifra <br> e o vetor de inicialização (iv)
        %%  clientOptionHandler, linha 488 ou perto. HELP.
        C1 ->> C1: calcula o HMAC da mensagem cifrada
        C1 ->> C1: calcula a assinatura digital da mensagem cifrada <br> com a chave privada RSA
        C1 ->> S: envia nome de utilizador (próprio), nome de utilizador do segundo cliente, <br> mensagem cifrada, vetor de inicialização (iv), HMAC, <br> n, e, assinatura digital

        S ->> S: decifra KEY com ivKey (parâmetro do sistema) <br> e vetor de inicialização (iv)
        S ->> S: obtém a chave de cifra, a chave de HMAC e p <br> ao dividir a KEY
        S ->> S: calcula q = N / p
        S ->> S: faz ataque de força bruta para descobrir d
        S ->> S: constrói a chave privada RSA com N, e, d, p, q
        S ->> S: decifra a mensagem cifrada com a chave de cifra <br> e o vetor de inicialização (iv)
        S ->> S: guarda texto-limpo num ficheiro
        S ->> S: espera 15 segundos
        note right of S: a mensagem pode agora ser alterada

        S ->> S: cifra a mensagem
        S ->> S: calcula HMAC da mensagem cifrada
        S ->> S: calcula a assinatura digital da mensagem cifrada
        S ->> D: envia nome de utilizador (próprio), nome de <br> utilizador (amigo) e mensagem não cifrada
        D ->> D: armazena a mensagem
        S ->> C2: envia nome de utilizador inicial, nome do amigo, <br> criptograma, iv, HMAC, N, e, assinatura digital
    end

```
- A troca de chaves é feita a cada início de chat com outro utilizador


### Outros Diagramas

#### Menu Inicial

```mermaid
sequenceDiagram
    participant C as Cliente
    participant S as Servidor

    %% inicialização
    S ->> S: inicia as sockets e threads <br> e fica à escuta de comunicações
    C ->> C: inicia as threads
    C ->> S: inicia os sockets de chaves e de mensagem
    C ->> C: vê menu inicial

    %% registar
    alt Efetuar Registo
        C ->> C: vê menu de registo
        C ->> S: inicia a socket principal \ <br> pedido para efetuar registo
        S ->> S: aloca uma thread ao cliente
        C -->> S: registo por CHAP
        C -->> S: registo por Schnorr
        note right of C: ver diagrama de registo

    %% login
    else Efetuar Login
        C ->> C: vê menu de login
        C ->> S: inicia a socket principal \ <br> pedido para efetuar login
        S ->> S: aloca uma thread ao cliente
        C -->> S: login por CHAP
        C -->> S: login por Schnorr
        note right of C: ver diagrama de login

    %% sair
    else Sair
        C ->> S: terminar sockets de chave e de mensagem
        C ->> C: terminar threads
        C ->> C: terminar o processo
    end
```

#### Menu Principal

```mermaid
sequenceDiagram
    participant C as Cliente
    participant S as Servidor
    participant D as Base de Dados

    C ->> C: vê menu principal
    
    %% menu de amigos
    alt Menu de amigos
        C ->> C: escolhe menu de amigos
        C ->> C: vê menu de amigos
        note right of C: ver diagrama de menu de amigos

    %% troca de mensagens >> isto é o diagrama acima, right?
    else Conversar com amigos
        C ->> C: seleciona opção de conversar com um amigo
        C ->> S: inicia socket principal \ <br> pedido para iniciar chat
        S ->> D: envia query para verificar os amigos online
        D ->> D: executa query
        D ->> S: envia resultado da query
        note right of S: não há amigos online
        S ->> C: envia de mensagem de aviso
        note right of S: há amigos online
        S ->> C: envia lista de amigos online
        C ->> C: escolhe o amigo com quem quer conversar
        C ->> S: início do chat
        note right of S: ver diagrama de troca de mensagens

    %% sair
    else Sair
        C ->> C: escolhe opção de logout
        C ->> S: envia pedido de logout
        S ->> S: remove nome de utilizador da lista de sockets
        S ->> C: envia mensagem de sucesso
        C ->> C: vê menu inicial
    end
```

#### Menu de Amigos

```mermaid
sequenceDiagram
    participant C as Cliente
    participant S as Servidor
    participant D as Base de Dados

    C ->> C: vê menu de amigos

    %% adicionar amigo
    alt Adicionar amigo
        C ->> S: inicia socket principal \ <br> pedido de adicionar um amigo
        C ->> S: envia nome de utilizador (próprio) <br> e nome de utilizador do segundo cliente
        S ->> D: envia query de pesquisa pelo nome de utilizador do segundo cliente
        D ->> D: executa a query
        D ->> S: envia resultado da query
        note right of S: se o nome de utilizador do segundo cliente <br> é o mesmo nome de utilizador do primeiro cliente
        S ->> C: envia mensagem de aviso
        note right of S: se o nome de utilizador do segundo cliente <br> não existe na base de dados
        S ->> C: envia mensagem de aviso
        note right of S: se o nome de utilizador do segundo cliente <br> já está na lista de pedidos de amizade <br> do primeiro cliente
        S ->> C: envia mensagem de aviso
        note right of S: se os dois utilizadores já estão guardados <br> na base de dados como amigos
        S ->> C: envia mensagem de aviso
        note right of S: se nenhuma das possibilidades acima se cumpriu
        S ->> D: envia query para guardar o pedido de amizade <br> a título temporário
        D ->> D: executa a query
        S ->> C: envia mensagem de sucesso

    %% pedidos de amizade
    else Pedidos de amizade
        C ->> S: inicia socket principal \ <br> pedido de verificar pedidos de amizade
        C ->> S: envia nome de utilizador (próprio)
        S ->> D: envia query de pesquisa pelo nome de utilizador <br> para pedidos de amizade pendentes
        D ->> D: executa a query
        D ->> S: envia resultado da query
        note right of S: não existem pedidos pendentes
        S ->> C: envia mensagem de aviso
        note right of S: existe uma lista de pedidos pendentes
        S ->> C: envia lista de pedidos de amizade
        C ->> C: escolhe os utilizadores (pelo seu índice) <br> que quer aceitar como amigos
        C ->> C: escolhe os utilizadores (pelo seu índice) <br> que não quer aceitar como amigos
        C ->> S: envia nome de utilizador (próprio), <br> lista de pedidos a aceitar, <br> lista de pedidos a recusar
        S ->> D: envia query de aceitação de pedidos de amizade
        D ->> D: executa a query
        S ->> D: envia query de rejeição de pedidos de amizade
        D ->> D: executa a query
        S ->> C: envia mensagem de sucesso

    %% verificar lista de amigos
    else Verificar lista de amigos
        C ->> S: inicia socket principal \ <br> pedido de verificar a lista de amigos
        C ->> S: envia nome de utilizador (próprio)
        S ->> D: envia query de pesquisa pelo nome de utilizador <br> para pedidos de amizade aceites
        D ->> D: executa a query
        D ->> S: envia resultado da query
        note right of S: não existem amigos
        S ->> C: envia mensagem de aviso
        note right of S: existe uma lista de amigos
        S ->> C: envia lista de amigos

    %% remover amigo
    else Remover amigo
        C ->> S: inicia socket principal \ <br> pedido de remover amizade
        C ->> S: envia nome de utilizador (próprio) <br> e nome de utilizador do segundo cliente
        S ->> D: envia query de pesquisa pelo nome de utilizador <br> para pedidos de amizade aceites
        D ->> D: executa a query
        D ->> S: envia resultado da query
        note right of S: não existem amigos
        S ->> C: envia mensagem de aviso
        note right of S: existe uma lista de amigos
        S ->> C: envia lista de amigos
        C ->> C: escolhe o utilizador (pelo seu índice) <br> que quer remover da lista de amizades
        C ->> S: envia nome de utilizador (próprio) e índice
        S ->> D: envia query de remoção de pedidos de amizade
        D ->> D: executa a query
        S ->> C: envia mensagem de sucesso
    
    %% sair
    else Sair
        C ->> C: vê menu principal
    end
```