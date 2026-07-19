# Contribuindo

Muninn segue um escopo pequeno: inspecao local e somente leitura de trafego
HTTP/HTTPS. Edicao de requests, scanning, repeater e automacao de pentest ficam
fora do projeto.

Antes de enviar uma mudanca:

```sh
make
make check
make fuzz-smoke
make sanitize
make thread-sanitize
```

`make fuzz-http` e opcional e requer Clang com libFuzzer. Mudancas no parser,
framing, TLS, captura ou decodificacao devem incluir um teste focado. Comentarios
explicativos sao escritos em portugues brasileiro; identificadores e contratos
publicos permanecem concisos e em ingles.

Nao adicione certificados, chaves privadas, capturas reais ou credenciais ao
repositorio.
