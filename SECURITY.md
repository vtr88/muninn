# Seguranca

## Modelo de uso

Muninn e um inspetor local e somente leitura. Ele escuta exclusivamente em
`127.0.0.1`, encaminha o trafego sem pausa ou modificacao e mantem o historico
somente na memoria do processo.

Ele nao e um isolamento de seguranca, scanner de vulnerabilidades ou protecao
contra conteudo malicioso. O parser e os decodificadores recebem dados nao
confiaveis vindos da rede; execute apenas uma versao em que voce confia.

## Autoridade certificadora

`muninn-ca-key.pem` permite emitir certificados aceitos por navegadores que
confiam na CA do Muninn. Essa chave:

- deve permanecer com permissao `0600`;
- nunca deve ser importada no navegador;
- nunca deve ser compartilhada ou adicionada ao Git;
- deve ser removida junto com a confianca na CA quando nao for mais usada.

Use preferencialmente um perfil separado do Firefox. Nao execute o Muninn como
root. A opcao `--insecure-upstream` reduz a seguranca e deve ficar restrita a
servidores de desenvolvimento deliberadamente autofirmados.

## Dados observados

Requests podem conter cookies, tokens, senhas e dados pessoais. O Muninn nao
persiste o historico nem oferece exportacao, mas esses dados permanecem na
memoria ate serem descartados, limpos com `C` ou apagados ao encerrar.

## Relato de falhas

Nao publique chaves, credenciais, dumps de trafego ou provas contendo dados de
terceiros. Envie um relato privado ao mantenedor pelo endereco disponivel no
perfil do repositorio, com uma descricao reproduzivel e sem dados sensiveis.
