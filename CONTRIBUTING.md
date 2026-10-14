# Como contribuir com o Prosa

Obrigado pelo interesse! O Prosa é feito pela comunidade, para a comunidade.

## Por onde começar

- Procure issues com as etiquetas `boa primeira issue` ou `ajuda bem-vinda`.
- Quer propor algo maior? Abra uma issue para discutir antes de escrever o código.
- Revisão de segurança e da criptografia é especialmente bem-vinda.

## Ambiente

```sh
# Servidor
cd server
go test ./...                                                            # testes unitários
PROSA_TEST_DATABASE_URL=postgres://localhost/prosa_test go test -race ./... # + integração

# Pacotes TypeScript
npm ci
npm run typecheck
PROSA_TEST_DATABASE_URL=postgres://localhost/prosa_test npm test         # inclui teste ponta a ponta
```

Ou suba tudo com `docker compose up --build`.

## Convenções

- **Idioma**: código, nomes e identificadores em inglês; comentários, mensagens de erro para o usuário, documentação e discussões em português.
- **Go**: `gofmt`, `go vet`, sem dependências desnecessárias.
- **TypeScript**: modo `strict`; sem dependências de plataforma em `@prosa/crypto` (precisa rodar em React Native, navegador e Node).
- **Testes**: toda mudança de comportamento vem com teste. Mudanças no protocolo ou na API precisam passar no teste ponta a ponta.
- **Commits**: mensagens claras no imperativo (ex.: "Adiciona rotação da signed prekey").

## Regras para criptografia

- Nunca implemente primitivas próprias: use `@noble/*` (clientes) e a biblioteca padrão do Go (servidor).
- Mudanças em `packages/crypto` precisam de revisão de pelo menos duas pessoas e de testes cobrindo adulteração, replay e ordem das mensagens.
- Qualquer alteração no formato no fio deve incrementar a versão e ser documentada em `docs/seguranca.md`.

## Licença

Ao contribuir, você concorda em licenciar sua contribuição sob a [GPL-3.0](LICENSE).
