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
    C ->> S: envia pedido de registo
    S ->> C: envia pedido de credenciais (nome de utilizador)
    C ->> S: envia o nome de utilizador
    note right of C: o atacante consegue apanhar o pacote <br> ao fazer sniffing, por exemplo, com o Wireshark
    S -> S:  a base de dados guarda os dados da Alice <br> (a Alice fica como utilizador temporário)
    S ->> C: envia pedido de credenciais (palavra-passe)
    C -> C:  (está a pensar na palavra-passe)

    A ->> A: vê menu de registo
    A ->> A: escolhe método de registo (CHAP)
    A ->> S: envia pedido de registo
    S ->> A: envia pedido de credenciais (nome de utilizador)
    A ->> S: envia o nome de utilizador da Alice
    S -> S:  a base de dados remove os dados temporários da Alice
    S ->> A: envia pedido de credenciais (palavra-passe)
    A ->> S: envia palavra-passe
    S ->> A: regista o atacante como sendo a Alice

    C ->> S: envia palavra-passe
    S ->> C: aceita o registo
    C ->> C: vê menu de login
    C ->> C: escolhe método de login (CHAP)
    C ->> S: envia pedido de login
    S ->> C: envia pedido de credenciais (nome de utilizador)
    C ->> S: envia o nome de utilizador
    S ->> C: recusa o pedido de login
```