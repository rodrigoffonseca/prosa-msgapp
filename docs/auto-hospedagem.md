# Auto-hospedagem e soberania dos dados

Um dos pilares do Prosa é que **os dados ficam onde você decide**. Uma prefeitura, universidade, empresa, sindicato ou associação pode rodar seu próprio servidor, em datacenter no Brasil, sob a legislação brasileira.

## Requisitos

- Linux com Docker (ou o binário Go compilado), 1 vCPU e 1 GB de RAM atendem milhares de usuários.
- PostgreSQL 16.
- Domínio com HTTPS (recomendamos Caddy ou Nginx como proxy reverso).
- Um provedor de SMS (de preferência nacional) acessível via um pequeno serviço HTTP seu.

## Configuração

Todas as opções são variáveis de ambiente (veja [.env.example](../.env.example)):

| Variável | Padrão | Descrição |
| --- | --- | --- |
| `PROSA_ENV` | `development` | Use `production`: o servidor passa a recusar configurações inseguras |
| `PROSA_LISTEN_ADDR` | `:8080` | Endereço HTTP |
| `PROSA_DATABASE_URL` | `postgres://prosa:prosa@localhost:5432/prosa` | Conexão com o PostgreSQL |
| `PROSA_PHONE_PEPPER` | — | **Obrigatório em produção.** 32 bytes em hex (`openssl rand -hex 32`). Faça backup seguro: sem ele, ninguém consegue entrar pelo número |
| `PROSA_SMS_PROVIDER` | `console` | `webhook` em produção |
| `PROSA_SMS_WEBHOOK_URL` / `_KEY` | — | Serviço que envia o SMS (veja abaixo) |
| `PROSA_TRUST_PROXY_HEADERS` | `false` | `true` atrás de proxy reverso, para limitar por IP real |
| `PROSA_BLOB_DIR` | `./data/blobs` | Onde guardar anexos cifrados |
| `PROSA_MAX_ATTACHMENT_BYTES` | 25 MiB | Tamanho máximo de anexo |
| `PROSA_RETENTION_DAYS` | `30` | Validade de mensagens não entregues e anexos |

### Webhook de SMS

O Prosa não se prende a nenhum fornecedor. Ele faz:

```http
POST {PROSA_SMS_WEBHOOK_URL}
Authorization: Bearer {PROSA_SMS_WEBHOOK_KEY}
Content-Type: application/json

{"to": "+5511987654321", "message": "Seu código Prosa é 123456. Não compartilhe com ninguém."}
```

Qualquer resposta 2xx é sucesso. Basta um pequeno serviço que repasse para a API do seu provedor de SMS.

## LGPD

O desenho do servidor ajuda o controlador a cumprir a LGPD:

- **Minimização** (art. 6º, III): conteúdo cifrado de ponta a ponta; telefone em HMAC; sem log de IP.
- **Eliminação** (art. 18, VI): `DELETE /v1/me` apaga a conta e tudo associado.
- **Retenção limitada** (art. 15–16): mensagens são apagadas na entrega; o restante, após o prazo configurado.
- **Segurança** (art. 46): mesmo com o banco vazado, o conteúdo das conversas continua ilegível.

Quem hospeda continua sendo o controlador dos dados e deve manter sua própria política de privacidade, registro de operações e encarregado (DPO).

## Backups

Faça backup do PostgreSQL, do diretório de anexos e, separadamente e com cuidado redobrado, do `PROSA_PHONE_PEPPER`.
