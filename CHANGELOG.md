# Changelog

Todas as mudancas relevantes do Muninn serao registradas neste arquivo.

## 0.1.0 - 2026-07-19

Primeira release funcional do inspetor somente leitura.

### Incluido

- Proxy HTTP/1.x sem bloqueio ou modificacao de trafego.
- MITM HTTPS local com CA propria e certificados por host em cache.
- Verificacao TLS upstream, SNI, ALPN HTTP/1.1 e modo passthrough.
- Historico estruturado inteiramente em memoria.
- TUI com lista de transacoes e detalhes de Request e Response.
- Busca por texto e filtros `method:`, `host:`, `status:` e `state:`.
- Visualizacao textual e hexdump de bodies binarios.
- Decodificacao para exibicao de gzip, deflate e Brotli.
- Limites configuraveis, truncamento explicito e descarte de historico antigo.
- Testes unitarios, teste concorrente, sanitizers e harness de fuzz locais.
