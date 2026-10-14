# Segurança e criptografia

> Este documento descreve o que o Prosa protege, como, e — tão importante quanto — o que **ainda não** protege. A implementação ainda não foi auditada de forma independente.

## Objetivos

1. **Confidencialidade do conteúdo** — só remetente e destinatários leem mensagens, fotos e áudios. Nem quem opera o servidor, nem quem invade o servidor, nem quem intercepta a rede.
2. **Integridade e autenticidade** — mensagens adulteradas são rejeitadas; o destinatário sabe qual identidade enviou.
3. **Sigilo futuro (*forward secrecy*)** — o vazamento das chaves de hoje não revela mensagens passadas.
4. **Recuperação pós-comprometimento** — depois de um vazamento, a conversa volta a ficar segura assim que novas chaves efêmeras são trocadas.
5. **Coleta mínima** — o servidor guarda o mínimo de metadados, pelo menor tempo possível.

## Primitivas

| Uso | Algoritmo | Biblioteca |
| --- | --- | --- |
| Identidade / assinaturas | Ed25519 | `@noble/curves` |
| Acordo de chaves | X25519 (identidade convertida Edwards→Montgomery) | `@noble/curves` |
| Derivação de chaves | HKDF-SHA-256, HMAC-SHA-256 | `@noble/hashes` |
| Cifra de mensagens e anexos | AES-256-GCM | `@noble/ciphers` |
| Número de segurança | SHA-512 iterado (5200×) | `@noble/hashes` |

As bibliotecas `@noble/*` são JavaScript puro, sem dependências, e passaram por auditorias independentes.

## Protocolo

### X3DH (início de sessão)

Segue a [especificação X3DH do Signal](https://signal.org/docs/specifications/x3dh/):

- `SK = HKDF(0xFF×32 ‖ DH(IKa, SPKb) ‖ DH(EKa, IKb) ‖ DH(EKa, SPKb) [‖ DH(EKa, OPKb)])`, info `Prosa_X3DH_v1`.
- A assinatura Ed25519 da *signed prekey* é verificada antes de qualquer uso.
- Dados associados (AD) = `IKa ‖ IKb`, incluídos em todo AEAD da sessão.
- Pontos de ordem baixa (resultado DH nulo) são rejeitados.
- *One-time prekeys* são apagadas do aparelho após o uso; uma *PreKey message* repetida (replay) é recusada.
- Enquanto o destinatário não responde, o remetente continua enviando *PreKey messages*, para que a sessão se estabeleça mesmo se a primeira mensagem se perder.
- Se os dois lados iniciarem sessão ao mesmo tempo, cada lado guarda até 4 sessões anteriores e converge para a que o outro está usando.

### Double Ratchet (cada mensagem)

Segue a [especificação do Double Ratchet](https://signal.org/docs/specifications/doubleratchet/):

- `KDF_RK`: HKDF-SHA-256 (info `Prosa_Ratchet_v1`); `KDF_CK`: HMAC-SHA-256 com constantes `0x01`/`0x02`.
- Chave e nonce do AES-256-GCM derivados da chave da mensagem via HKDF (info `Prosa_MessageKeys_v1`) — cada chave cifra uma única mensagem.
- Cabeçalho (chave do ratchet, PN, N) autenticado como dado associado.
- Mensagens fora de ordem: até 1000 por cadeia, até 2000 chaves guardadas por sessão.
- Decifração transacional: uma mensagem forjada não altera o estado da sessão.

### Formato no fio

```
Mensagem:        0x01 0x02 ‖ cabeçalho(40) ‖ AES-GCM(conteúdo)
PreKey message:  0x01 0x01 ‖ IKa(32) ‖ EKa(32) ‖ id_SPK(4) ‖ tem_OPK(1) ‖ id_OPK(4) ‖ mensagem
```

O conteúdo é um JSON (tipo, texto, ponteiro de anexo, grupo, `registration_id` do remetente, horário) preenchido com `0x80 00…` até múltiplo de 160 bytes, para não revelar o tamanho exato do texto.

### Anexos

Cada foto ou áudio é cifrado com uma chave AES-256 aleatória e nonce aleatório. O servidor guarda só os bytes cifrados; chave e SHA-256 viajam na mensagem E2EE. O destinatário confere o SHA-256 antes de decifrar.

### Verificação de identidade

- **TOFU** (*trust on first use*): a primeira chave de identidade vista de um contato é registrada.
- Se a chave mudar (reinstalação ou ataque), o SDK emite `identityChanged`. Com `identityChangePolicy: 'reject'`, a comunicação é bloqueada até o usuário confirmar.
- **Número de segurança**: 60 dígitos, iguais nos dois aparelhos, para comparar pessoalmente ou por QR code — é o que derrota um servidor malicioso que tente se passar por um contato.

## O que o servidor vê (metadados)

Sendo transparentes — no MVP o servidor **vê**:

- que uma conta existe e o HMAC do seu telefone (não o número em claro, mas números de telefone são um espaço pequeno: quem tiver o *pepper* consegue testar todos — proteja o *pepper*);
- `@nome` e nome de exibição;
- quem envia para quem e quando (até a entrega), e o tamanho aproximado (com padding) de cada mensagem;
- nome, membros e administradores dos grupos;
- tamanho dos anexos;
- endereço IP das conexões (não é gravado em log pelo servidor, mas está disponível para quem opera a rede).

O servidor **não vê**: conteúdo de mensagens, fotos, áudios, legendas, tipo de mensagem, chaves privadas, tokens de sessão em claro.

O que está no roteiro para reduzir metadados: *sealed sender* (esconder o remetente), metadados de grupo cifrados, descoberta de contatos com privacidade.

## Proteções do servidor

- Telefone guardado como HMAC; tokens e códigos guardados como hash.
- Código SMS: 6 dígitos, 10 minutos, 5 tentativas, uso único; limite de pedidos por número e por IP (limites por IP generosos por causa do CGNAT das operadoras móveis).
- Limite de buscas por telefone e de consumo de *prekeys* por usuário (contra enumeração e esgotamento de chaves).
- Logs sem IP, sem query string e sem cabeçalhos.
- Retenção limitada: envelopes não entregues e anexos são apagados após 30 dias (configurável); envelopes entregues são apagados na confirmação.
- Exclusão de conta apaga todos os dados associados (LGPD, art. 18).
- Em produção, o servidor se recusa a subir com configurações de desenvolvimento (SMS no console, código exposto, *pepper* padrão).

## Limitações conhecidas (MVP)

- **Sem auditoria independente** ainda.
- Um aparelho por conta.
- *Signed prekey* não é rotacionada periodicamente (rotação a cada reinstalação apenas).
- O armazenamento local de chaves no app ainda precisa ser implementado sobre Keychain/Keystore e banco cifrado.
- Remetente visível ao servidor (sem *sealed sender*).
- Nome e membros de grupo visíveis ao servidor.

## Reportando vulnerabilidades

Veja [SECURITY.md](../SECURITY.md).
