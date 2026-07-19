# Muninn

```text
                              ___
                          _.-'   '-._
                       .-'           '.
                     .'      __        \
                    /      .'  '.       |
                   ;      /  o   \      |
                   |      \      /  _.-'-----.__
                    \      '----'.-'            _ '>
                     '._        /      __..---''
                        '--.___/__.---'
                              / /
                         ____/ /____
                        /___________\
                         Muninn observa.
```

### 1. Instale as dependencias
No Debian:
```sh
sudo apt install build-essential libncurses-dev libssl-dev
```
### 2. Compile
```sh
make
```
O executavel sera criado como `./muninn`.
### 3. Crie ou valide a CA local
```sh
./muninn ca create
```
Esse comando prepara:
```text
muninn-ca-cert.pem  certificado publico para importar no navegador
muninn-ca-key.pem   chave privada que deve permanecer somente nesta maquina
```
Nunca importe, compartilhe ou envie `muninn-ca-key.pem`.
Para conferir a identidade da CA:
```sh
./muninn ca fingerprint
```
### 4. Importe a CA no Firefox
Use preferencialmente um perfil separado do Firefox para os testes.

1. Abra **Configuracoes**.
2. Entre em **Privacidade e Seguranca**.
3. Procure a secao **Certificados**.
4. Clique em **Ver certificados**.
5. Abra a aba **Autoridades**.
6. Clique em **Importar**.
7. Selecione `muninn-ca-cert.pem`.
8. Autorize essa CA a identificar sites.

Importe somente `muninn-ca-cert.pem`.

### 5. Inicie o Muninn
```sh
./muninn
```
Ele deve mostrar que esta ouvindo em:
```text
127.0.0.1:13337
```
Mantenha esse terminal aberto.

### 6. Configure o proxy no Firefox

1. Abra **Configuracoes**.
2. Na secao **Geral**, procure **Configuracoes de rede**.
3. Clique em **Configurar**.
4. Selecione **Configuracao manual de proxy**.
5. Em **Proxy HTTP**, informe `127.0.0.1`.
6. Em **Porta**, informe `13337`.
7. Marque a opcao para usar esse proxy tambem em HTTPS.
8. Confirme as alteracoes.

Nao adicione os sites que deseja observar na lista **Sem proxy para**.

### 7. Navegue

Abra um site HTTP ou HTTPS no Firefox. O Muninn encaminhara a conexao e
mostrara o trafego nas abas:
```text
C->S  navegador para servidor
S->C  servidor para navegador
```
Use `Tab` ou as setas esquerda/direita para trocar de aba. Pressione `q`
para encerrar.
Se um site usar certificate pinning e recusar o MITM, reinicie com passthrough:
```sh
./muninn --passthrough exemplo.com
```
Nesse modo o site funciona, mas seu HTTP permanece cifrado e nao pode ser
mostrado pelo Muninn.
`--insecure-upstream` desativa a verificacao dos certificados dos servidores
reais. Use essa opcao somente para servidores de desenvolvimento cujo
certificado invalido seja esperado:
```sh
./muninn --insecure-upstream
```
### 8. Depois dos testes

1. Pressione `q` para encerrar o Muninn.
2. Volte as configuracoes de rede do Firefox para **Sem proxy** ou para a
   configuracao usada anteriormente.
3. No gerenciador de certificados do Firefox, remova ou deixe de confiar em
   **Muninn Local CA**.

Sem o proxy ativo, o Firefox configurado para `127.0.0.1:13337` nao conseguira
navegar. Remover a confianca da CA depois dos testes evita que ela continue
valida para interceptacao futura.
