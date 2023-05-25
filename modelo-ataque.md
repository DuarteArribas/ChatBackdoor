# Modelo de Ataque

Notas iniciais:
* As sockets não estão protegidas pela Secure Socket Layer, pelo que podem ser vistas por qualquer utilizador que esteja a utilizar um *sniffer* sobre a rede;
* O modelo de ataque proposto é tanto passivo como ativo:
  * Passivo - o atacante conhece o nome do utilizador;
  * Ativo - o atacante impede o registo da pessoa e faz-se passar por ela.

```mermaid
sequenceDiagram
    participant C as Alice
    participant S as Servidor
    participant A as Atacante

    C ->> C: vê menu de registo
    C ->> C: escolhe método de registo (CHAP)
    C ->> S: envia pedido de registo \ <br> envia o nome de utilizador
    note right of C: o atacante consegue apanhar o pacote TCP <br> ao fazer sniffing, por exemplo, com o Wireshark
    S -> S:  a base de dados guarda os dados da Alice (real) <br> (a Alice (real) fica como utilizador temporário)
    S ->> C: envia pedido de credenciais (palavra-passe)
    C -> C:  (está a pensar na palavra-passe)

    A ->> A: vê menu de registo
    A ->> A: escolhe método de registo (CHAP)
    A ->> S: envia pedido de registo \ <br> envia o nome de utilizador da Alice
    S -> S:  a base de dados remove os dados temporários da Alice (real)
    S -> S:  a base de dados guarda os dados da Alice (atacante) <br> (a Alice (atacante) fica como utilizador temporário)
    S ->> A: envia pedido de credenciais (palavra-passe)
    A ->> S: envia palavra-passe
    S ->> S: regista o atacante como sendo a Alice
    S ->> A: envia mensagem de sucesso

    C ->> S: envia palavra-passe
    S ->> C: envia mensagem de sucesso
    C ->> C: vê menu de login
    C ->> C: escolhe método de login (CHAP)
    C ->> S: envia pedido de login \ <br> envia o nome de utilizador
    S ->> C: envia pedido de credenciais (palavra-passe)
    C ->> S: envia a palavra-passe
    note right of S: como o atacante se registou com uma <br> outra palavra-passe, o servidor não <br> consegue autenticar a Alice (real)
    S ->> C: recusa o pedido de login
```