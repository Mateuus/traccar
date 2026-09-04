# Web Push (VAPID) no Traccar da RDM

> **Antes de ler o resto: a maior parte disto já existe e está em produção desde 2026-08-30.**
> Este documento serve para (a) ninguém reconstruir o que já está feito, (b) explicar por que foi
> feito assim, e (c) especificar a invalidação na troca de senha, que é o único item pendente e
> está **adiado por decisão**, não por falta de desenho.

## O que a internet diz, e por que está desatualizado para nós

Pesquisar "Traccar VAPID" devolve, corretamente, que **o Traccar upstream não tem Web Push**. O
push móvel oficial dele é o `NotificatorFirebase`, amarrado ao app Traccar Manager, e a receita
recomendada por terceiros é encaminhar os eventos por *webhook* para um microserviço que cifra e
envia.

Nós não seguimos essa receita. Foram três razões:

1. **Uma peça a menos.** Microserviço é mais um processo para subir, monitorar, autenticar e
   manter vivo. O notificator roda dentro da JVM que já existe.
2. **O Traccar continua sabendo o que aconteceu.** Com webhook, quem entrega é outro sistema: o
   Traccar não sabe se chegou, não limpa inscrição morta, e o registro de notificação mente.
3. **Latência.** Evento → notificator → push service. Sem fila intermediária, sem hop extra.

O canal se chama `webpush` e convive com o `web` do upstream. Não substitui: `web` entrega pelo
WebSocket (só alcança quem está com o painel aberto na frente) e é o caminho de menor latência para
quem está olhando o mapa; `webpush` é o que alcança o celular no bolso, com o app fechado.

## Esclarecendo o Firebase

Escolher VAPID **não** significa "não usar Google". Significa não usar o **SDK e a infraestrutura**
do Firebase. A distinção importa:

Cada navegador tem um *push service* próprio, escolhido pelo fabricante — não por nós:

| Navegador | Endpoint da inscrição | Operado por |
|---|---|---|
| Chrome / Chromium / Brave / Edge | `fcm.googleapis.com` | Google |
| Firefox | `updates.push.services.mozilla.com` | Mozilla |
| Safari (macOS e iOS) | `web.push.apple.com` | Apple |

O navegador se inscreve e devolve um **endpoint**. Nosso servidor cifra a mensagem e faz um POST
nessa URL, assinado com a nossa chave VAPID. Não há conta, credencial nem API do Google no meio, e
o mesmo código fala com a Apple sem mudar uma linha. Com o Firebase, mandaríamos a mensagem **para
o Google**, que a repassaria para esse mesmo endpoint — um hop a mais, um projeto a manter e um SDK
pesado no bundle.

Consequência prática de diagnóstico: um erro `Registration failed - push service error` acontece
**antes de o nosso servidor entrar na história**. É o navegador falhando ao se registrar no serviço
dele. O Brave, por exemplo, desliga esse serviço por padrão.

---

## Parte 1 — O que já está implementado

### Servidor (fork `Mateuus/traccar`)

| Arquivo | Papel |
|---|---|
| `src/main/java/org/traccar/notificators/webpush/WebPushKeys.java` | Chaves P-256 entre o formato do Web Push (ponto X9.62 + escalar, base64url) e o JCE |
| `src/main/java/org/traccar/notificators/webpush/WebPushEncryption.java` | Cifragem RFC 8291 sobre o formato `aes128gcm` do RFC 8188 |
| `src/main/java/org/traccar/notificators/webpush/VapidSigner.java` | Cabeçalho `Authorization` do RFC 8292 (JWT ES256) |
| `src/main/java/org/traccar/notificators/NotificatorWebPush.java` | O canal: carrega as inscrições, cifra, assina, envia, limpa inscrição morta |
| `src/main/java/org/traccar/api/resource/PushSubscriptionResource.java` | `GET /api/push/publicKey`, `GET /api/push/subscriptions`, `POST /api/push/subscribe`, `POST /api/push/unsubscribe` |
| `src/main/java/org/traccar/model/PushSubscription.java` | Entidade de `tc_push_subscriptions` |
| `schema/changelog-rdm-webpush.xml` | Criação da tabela |
| `src/test/java/org/traccar/notificators/webpush/` | Conformidade com o RFC + verificação da assinatura |

Registrado em `NotificatorManager` como `"webpush"`.

> ⚠️ `Map.of()` em `NotificatorManager` só tem sobrecarga até 10 pares, e `webpush` ocupa o décimo.
> Um notificator a mais exige trocar por `Map.ofEntries()`.

### Por que a criptografia é escrita à mão

Nenhuma dependência nova. As bibliotecas Java de web-push arrastam BouncyCastle e jose4j, e este
repositório é um fork que precisa continuar fazendo merge do upstream sem brigar por dependência.
Tudo o que é preciso já está no JCE do JDK: ECDH P-256, HKDF via HMAC-SHA256, AES-128-GCM e ECDSA.

A contrapartida é que a correção precisa ser **provada**, não afirmada. `WebPushEncryptionTest`
reproduz o vetor da seção 5 do RFC 8291 **byte a byte** e confere cada etapa em separado — ECDH,
HKDF, CEK, nonce e a montagem do corpo. Se um dia quebrar, a asserção que falha aponta o passo
exato em vez de dizer só "não funciona". `VapidSignerTest` desfaz a conversão DER→JOSE e pede ao
próprio JCE que valide a assinatura, porque é ali que essa implementação erra em silêncio e o
sintoma seria um 403 sem pista nenhuma no corpo da resposta.

### Formato da mensagem

```
corpo = salt(16) || rs(4, big-endian) || idlen(1) || chave_pública_efêmera(65) || ciphertext
cabeçalhos = Authorization: vapid t=<JWT ES256>, k=<chave pública VAPID>
             Content-Encoding: aes128gcm
             TTL: <segundos>
             Urgency: high
```

### Painel (`traccar-nextjs`)

| Arquivo | Papel |
|---|---|
| `worker/index.ts` | Handlers `push` e `notificationclick` — o custom worker que o next-pwa importa no `sw.js` |
| `src/lib/push/webPush.ts` | Inscrição, cancelamento, revalidação, e o religar do canal nas regras |
| `src/components/settings/PushDeviceCard.tsx` | "Alertas neste aparelho", em **Minha conta** |
| `src/components/settings/PushSubscriptionsCard.tsx` | "Aparelhos que recebem alertas" — a lista do servidor, com remover por linha |
| `src/lib/push/deviceLabel.ts` | `User-Agent` → "Chrome no Android". Sem biblioteca, e diz "não sei" em vez de chutar |
| `src/components/common/PushEnablePrompt.tsx` | Convite ao abrir o painel, adiável por 30 dias |

---

## Parte 2 — Configuração

O par VAPID é **por instância**. Não reaproveitar o de desenvolvimento em produção: quem tem a
chave privada consegue enviar notificação em nome do servidor.

### Gerar o par

```bash
# a partir do repositório do fork, com as classes compiladas
./gradlew assemble
java -cp build/classes/java/main -e '...'   # ou usar o utilitário de scratchpad GenVapid
```

Ou com o `openssl`, extraindo os bytes crus:

```bash
openssl ecparam -name prime256v1 -genkey -noout -out vapid.pem
# privada: escalar de 32 bytes em base64url
openssl ec -in vapid.pem -outform DER 2>/dev/null | tail -c +8 | head -c 32 \
  | base64 -w0 | tr '+/' '-_' | tr -d '='
# pública: ponto não comprimido de 65 bytes em base64url
openssl ec -in vapid.pem -pubout -outform DER 2>/dev/null | tail -c 65 \
  | base64 -w0 | tr '+/' '-_' | tr -d '='
```

**Conferência obrigatória** antes de usar: a pública tem de ter 87 caracteres, decodificar para 65
bytes, começar com `0x04` e o ponto tem de estar na curva P-256. Chave malformada faz o navegador
falhar na inscrição com uma mensagem genérica que não aponta a causa.

### Opção A — `traccar.xml` (instalação por systemd, como o servidor de dev)

```xml
<entry key='notificator.types'>web,mail,command,webpush</entry>
<entry key='notificator.webpush.publicKey'>B...</entry>
<entry key='notificator.webpush.privateKey'>...</entry>
<entry key='notificator.webpush.subject'>mailto:contato@rdmrastreamento.com.br</entry>
<entry key='notificator.webpush.ttl'>3600</entry>
```

### Opção B — variáveis de ambiente (Docker, como produção)

Só funciona com `CONFIG_USE_ENVIRONMENT_VARIABLES: "true"`. **Sem isso, todas as variáveis são
ignoradas em silêncio** — é o erro clássico de primeiro deploy.

A conversão de nome é `chave.comPonto` → `CHAVE_COM_PONTO`: pontos viram `_` e cada maiúscula ganha
um `_` antes (`Config.getEnvironmentVariableName`). Ou seja:

```yaml
NOTIFICATOR_TYPES: "web,mail,command,webpush"
NOTIFICATOR_WEBPUSH_PUBLIC_KEY: "B..."
NOTIFICATOR_WEBPUSH_PRIVATE_KEY: "..."
NOTIFICATOR_WEBPUSH_SUBJECT: "mailto:contato@rdmrastreamento.com.br"
```

> ⚠️ O default de `notificator.types` no upstream é `web,mail,command`. **Sem acrescentar
> `webpush` a lista, o canal não aparece na tela nem é instanciado** — e nada denuncia isso.

### A chave pública nunca vai embutida no cliente

O painel busca em `GET /api/push/publicKey`. Se o par for rotacionado no servidor, um cliente com a
chave antiga se inscreveria numa chave que o servidor não assina mais, e as entregas morreriam com
**403 mudo**. Por isso o cliente também compara os bytes da `applicationServerKey` da inscrição
existente com a chave atual e se re-inscreve sozinho quando divergem.

---

## Parte 3 — Vários aparelhos na mesma conta

**Já funciona, por desenho.** A modelagem é uma linha por *endpoint*, não por usuário:

```sql
tc_push_subscriptions(id, userid, endpoint UNIQUE, publickey, authsecret, useragent, createdat)
```

- Dois celulares logados na mesma conta = dois endpoints distintos = duas linhas com o mesmo
  `userid`. `NotificatorWebPush` carrega **todas** as linhas do usuário e envia para cada uma.
- O `endpoint` é único porque é ele que identifica a inscrição. Sem essa restrição, reabrir o
  painel no mesmo aparelho criaria linha nova a cada visita e o usuário receberia a mesma
  notificação N vezes.
- Se **outro** usuário fizer login no mesmo navegador, a linha **troca de dono** em vez de
  duplicar: mesmo endpoint, `userid` novo. É por isso que o logout precisa chamar `unsubscribe` —
  sem isso o próximo usuário daquele aparelho herdaria os alertas do anterior, o que é vazamento
  entre contas e não apenas incômodo.
- Envio é *best-effort* e independente por aparelho: um celular fora do ar não impede a entrega no
  outro. Resposta 404 ou 410 do push service significa inscrição morta e a linha é apagada.
- **Gerenciar os aparelhos é a tela "Aparelhos que recebem alertas"**, abaixo do "Alertas neste
  aparelho" em Minha conta. Ela lê `GET /api/push/subscriptions` — as linhas do usuário autenticado
  e só dele, sem `publicKey`/`authSecret`, que são material de cifragem. É por ali que se desliga o
  celular que foi trocado: ninguém consegue clicar em "Desativar" num navegador ao qual não tem
  mais acesso.
- ⚠️ Remover a linha marcada **"este aparelho"** tem de desfazer a inscrição no NAVEGADOR também, e
  não apenas no servidor. Só no servidor, o `pushState()` — que só sabe olhar o navegador —
  continuaria respondendo "granted" e o cartão de cima anunciaria "alertas ativos" para um aparelho
  que já não recebe nada. É a mesma mentira do 400 do Jackson, por outro caminho. Por isso a
  remoção do aparelho atual chama `disablePush()`, que desfaz os dois lados; os demais vão direto
  ao `unsubscribe`.
- Os dois cartões olham para fontes diferentes (um pergunta ao navegador, o outro ao servidor) e se
  avisam pelo `onPushChanged` do `webPush.ts`. Sem esse aviso, ativar em um deixaria o outro
  desatualizado até um F5.
- `ON DELETE CASCADE` no `userid`: conta apagada leva as inscrições junto.

---

## Parte 4 — Invalidar na troca de senha (ADIADO)

> **Status: adiado deliberadamente em 2026-08-31.** Não é esquecimento nem trabalho pela metade —
> foi decisão de priorização. O desenho abaixo está fechado e pronto para execução quando a decisão
> mudar. Enquanto isso, vale saber que **trocar a senha não derruba as inscrições existentes**.

Este é o único item novo. Hoje, trocar a senha **não** derruba as inscrições: quem já estava
inscrito continua recebendo. Para um sistema de rastreamento isso é um buraco real — trocar a senha
é justamente o que se faz quando se suspeita que alguém tem acesso indevido, e hoje esse alguém
continuaria recebendo a posição da frota no celular dele.

### Comportamento desejado

1. Senha alterada → **todas** as inscrições daquele usuário são apagadas, em todos os aparelhos.
2. Quem tinha a sessão aberta para de receber, sem aviso (é o efeito pretendido).
3. Na próxima abertura do painel, quem souber a senha nova se inscreve de novo — o
   `refreshPushIfGranted` já faz isso sozinho quando a permissão do navegador continua concedida.

### Os dois caminhos que gravam senha

Existem exatamente dois, e ambos precisam do gancho:

**1. `BaseObjectResource.update()` (`PUT /api/users/{id}`)** — usuário trocando a própria senha, ou
administrador trocando a de outro. A gravação da senha é condicional:

```java
if (entity instanceof User user) {
    if (user.getHashedPassword() != null) {
        storage.updateObject(entity, new Request(
                new Columns.Include("hashedPassword", "salt"),
                new Condition.Equals("id", entity.getId())));
    }
}
```

O `hashedPassword` só fica não-nulo quando `User.setPassword()` foi chamado com valor não vazio —
ou seja, esse `if` **é exatamente** "a senha mudou". É o ponto de gancho.

**2. `PasswordResource.update` (`POST /api/password/update`)** — recuperação por e-mail com token.

### Implementação sugerida

Um único método, chamado dos dois lugares:

```java
/**
 * Apaga todas as inscricoes de push do usuario.
 *
 * Chamado sempre que a senha muda. Trocar a senha e o que se faz ao suspeitar de acesso indevido;
 * sem isto, quem ja estava inscrito continuaria recebendo a posicao da frota no proprio celular,
 * porque a inscricao de push nao depende de sessao nem de cookie — ela vive no push service.
 */
private void revokePushSubscriptions(long userId) throws StorageException {
    storage.removeObject(PushSubscription.class, new Request(
            new Condition.Equals("userId", userId)));
}
```

Chamada logo depois de cada `updateObject` que grava `hashedPassword`.

**Onde colocar o método.** Duplicar em dois resources é ruim. Duas opções:

- **(a)** Um `PushSubscriptionService` injetável (`@Singleton`), usado pelos dois resources. Mais
  limpo, e é onde caberia futuramente a limpeza periódica de inscrições velhas.
- **(b)** Método estático num utilitário. Menos cerimônia, pior de testar.

Recomendação: **(a)**, porque o `BaseObjectResource` é código do upstream e cada linha acrescentada
ali é superfície de conflito no merge. Um serviço novo é arquivo novo — conflito zero. No
`BaseObjectResource` entra só a chamada de uma linha.

### Ponto de atenção

`BaseObjectResource.update()` é genérico (`<T>`) e serve a todas as entidades. O gancho tem de ficar
**dentro** do `if (entity instanceof User user)` que já existe, e **dentro** do `if` do
`hashedPassword` — senão qualquer edição de usuário (mudar o nome, o fuso, o mapa padrão) derrubaria
o push de todos os aparelhos dele, e o sintoma seria "as notificações param sozinhas de vez em
quando".

### Teste de aceitação

1. Inscrever dois navegadores diferentes na mesma conta; conferir duas linhas em
   `tc_push_subscriptions`.
2. Disparar um evento e confirmar que os dois recebem.
3. Trocar a senha pelo painel; conferir **zero** linhas para aquele usuário.
4. Disparar outro evento; confirmar que nenhum dos dois recebe.
5. Fazer login com a senha nova num deles; confirmar que uma linha volta e só ele recebe.
6. Editar o nome do usuário (sem tocar na senha) e confirmar que a inscrição **continua**.

---

## Parte 5 — Operação

**Rotação de chave.** Trocar o par invalida todas as inscrições (403 no envio). O cliente detecta
pela comparação da `applicationServerKey` e se re-inscreve, mas quem não abrir o painel fica sem
alerta até abrir. Rotacionar só com motivo, e de preferência apagando `tc_push_subscriptions` junto
para não acumular linha morta.

**Inscrição morta.** O envio apaga a linha ao receber 404 ou 410. Não existe limpeza periódica; se
um dia a tabela crescer demais, o lugar do varredor é o `PushSubscriptionService` da Parte 4.

**iPhone.** Push em PWA exige **iOS 16.4+ e o app instalado na tela de início**. Em aba comum do
Safari não existe. No Android funciona em aba normal, sem instalar. O Safari também ignora os
botões de ação da notificação e não aceita push silencioso — todo envio precisa mostrar algo, ou o
sistema revoga a permissão.

**Regras de notificação.** Cada regra do Traccar carrega a própria lista de canais (`notificators`),
e regra criada pela tela nasce só com `web`. Assinar o push sem `webpush` nas regras não entrega
nada, sem nenhum erro para explicar. Por decisão de produto não criamos regra automaticamente — que
eventos avisam é do administrador —, mas ativar os alertas liga o canal nas regras que já existem.

**A armadilha do Jackson (custou horas em 2026-08-31).** O ObjectMapper do Traccar **não** desliga
`FAIL_ON_UNKNOWN_PROPERTIES` (ver `MainModule.provideObjectMapper`). O `PushSubscription.toJSON()`
do navegador serializa **três** campos — `endpoint`, `keys` e `expirationTime` — e o DTO do resource
declarava só dois. O `expirationTime` sozinho fazia o Jackson recusar o corpo inteiro com 400.

O sintoma era enganoso a ponto de mandar a investigação para o lado errado:

- o navegador se inscrevia **com sucesso**;
- a tela dizia "alertas ativos" nas cargas seguintes, porque `pushState()` só consulta o navegador;
- o servidor nunca gravava nada — `tc_push_subscriptions` ficava vazia;
- nenhum push chegava, e o log do Traccar não registrava nada.

Duas correções: `@JsonIgnoreProperties(ignoreUnknown = true)` no DTO (igual ao que `Command` e
`Server` do upstream já fazem), e rollback no cliente — falhou o registro no servidor, desfaz a
inscrição do navegador, para o estado parar de mentir.

**Regra geral:** todo DTO que recebe JSON de fora precisa de `ignoreUnknown`. O navegador pode
acrescentar campo novo a qualquer momento, e a falha aparece como um 400 sem explicação.

**A armadilha do Jersey — `Content-Encoding` apagado em silêncio (corrigida em 2026-09-02).**
`Content-Encoding` é cabeçalho de **entidade**, e o Jersey reescreve os cabeçalhos de entidade a
partir da `Entity` na hora de serializar o corpo. Um `.header("Content-Encoding", "aes128gcm")`
posto no `Invocation.Builder` **é descartado** — sem exceção, sem log, sem nada na resposta. O
único jeito que funciona é declarar a codificação na entidade:

```java
Entity.entity(body, new Variant(MediaType.APPLICATION_OCTET_STREAM_TYPE, (Locale) null, "aes128gcm"))
```

O sintoma não aponta para o servidor em momento nenhum, e foi o que a investigação seguiu por horas:

- o push service **aceita** o POST (201, nada no log do Traccar);
- a notificação **chega** ao aparelho, no horário certo, com o ícone certo;
- mas o navegador recebe um corpo cifrado sem saber que é `aes128gcm`, então entrega o evento ao
  service worker com **`event.data` nulo**;
- o worker cai no fallback e mostra "RDM Rastreamento / Novo alerta na sua frota.", sem `tag` — daí
  também as dezenas de alertas empilhados, em vez de um por veículo (a `tag` vem no payload).

Ou seja: parece problema de template, de formatter ou de tradução, e não é nenhum dos três — o
payload sempre esteve certo, só chegou sem etiqueta de como abrir.

**Como conferir sem depender do navegador.** Crie uma inscrição sintética apontando para um
servidor HTTP seu (`endpoint` = `http://<host>:<porta>/diag`) com um par P-256 que você gerou,
dispare um evento e leia os cabeçalhos crus do POST. `Content-Encoding: aes128gcm` tem de estar lá.
Com a chave privada do par, o corpo capturado ainda pode ser decifrado (ECDH → HKDF → AES-GCM,
mesmos passos de `WebPushEncryption`, ao contrário) para conferir o JSON que o worker receberia.

**Idioma da notificação.** O texto sai do template de `templates/notifications/<idioma>/`, e o
idioma vem do atributo `language` do usuário ou do servidor (`UserUtil.getLanguage`). **Sem
`language` definido em nenhum dos dois, o `LocaleManager` cai em `en`** e a notificação chega em
inglês, mesmo com `pt_BR` presente na pasta. Não é bug do push: vale igual para e-mail e para o
canal `web`.

**Diagnóstico.** Erros de inscrição (`Registration failed - ...`) acontecem antes de o servidor
entrar na história: são do navegador com o push service dele. Erros de entrega aparecem no log do
Traccar como `Web push delivery failed with status N`.

---

## Como testar isto sem depender de um navegador real

Escrito depois de um dia inteiro perdido confiando na interface. **A regra número um: a tela mente.**
`pushState()` só consulta o navegador, então ela diz "alertas ativos" mesmo quando o servidor nunca
recebeu a inscrição. A única verdade é `tc_push_subscriptions`.

### O que NÃO funciona

- **Playwright / Chromium headless não consegue se inscrever.** `pushManager.subscribe()` devolve
  `AbortError: Registration failed - permission denied`. Builds do Chromium não têm as chaves do
  Google para falar com o serviço de push. Verificado. Não insista — teste o servidor por HTTP e o
  navegador só no aparelho de verdade.
- **Instalação de PWA não se testa por túnel de desenvolvimento.** O WebAPK é gerado pelos
  servidores do Google, que buscam manifest e ícones da URL pública.

### Receita: sessão autenticada sem saber a senha de ninguém

Cria um usuário temporário, testa, **apaga**. Nunca deixe a conta para trás.

```bash
# 1. Gerar hash+salt no formato do Traccar (usa a propria classe Hashing)
cat > /tmp/MakeHash.java <<'EOF'
import org.traccar.helper.Hashing;
public class MakeHash {
    public static void main(String[] a) {
        Hashing.HashingResult r = Hashing.createHash(a[0]);
        System.out.println("HASH=" + r.getHash());
        System.out.println("SALT=" + r.getSalt());
    }
}
EOF
./gradlew assemble
CP="build/classes/java/main:$(find target/lib -name 'commons-codec*.jar' | head -1)"
javac -cp "$CP" -d /tmp /tmp/MakeHash.java
java -cp "$CP:/tmp" MakeHash 'SenhaDeTeste!2026'
```

O `commons-codec` no classpath **não é opcional**: sem ele `Hashing.createHash` estoura com
`NoClassDefFoundError`.

```sql
-- 2. Inserir (ajuste hash/salt). O cliente mysql precisa rodar na rede do Docker:
--    docker run --rm --network <rede> -e MYSQL_PWD=... mysql:9.7 mysql -h traccar-db ...
INSERT INTO tc_users (name,email,hashedpassword,salt,administrator,disabled,readonly,devicelimit,userlimit)
VALUES ('DIAG','diag@exemplo.invalido','<HASH>','<SALT>',1,0,0,-1,0);
```

```bash
# 3. Logar e exercitar a API
curl -s -c /tmp/c.txt -X POST "$BASE/api/session" \
  --data-urlencode 'email=diag@exemplo.invalido' --data-urlencode 'password=SenhaDeTeste!2026'

curl -s -b /tmp/c.txt "$BASE/api/push/publicKey"              # tem de devolver 87 chars
curl -s -b /tmp/c.txt "$BASE/api/notifications/notificators"  # tem de listar "webpush"
```

```sql
-- 4. LIMPAR SEMPRE
DELETE FROM tc_push_subscriptions WHERE userid = <id>;
DELETE FROM tc_users WHERE email = 'diag@exemplo.invalido';
```

### Receita: inscrição sintética

Para exercitar gravação, listagem e remoção sem navegador. **Use um host inválido** — `.invalido`
não resolve e deixa claro que é teste; não escreva `fcm.googleapis.com`, que confunde quem lê o log.

```bash
curl -s -b /tmp/c.txt -X POST "$BASE/api/push/subscribe" -H 'Content-Type: application/json' -d '{
  "endpoint":"https://push.exemplo.invalido/envio/TESTE-1",
  "expirationTime":null,
  "keys":{
    "p256dh":"BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4",
    "auth":"BTBZMqHH6r4Tts7J_aSIgg"
  }}' -w '\nHTTP %{http_code}\n'
```

O `expirationTime` no corpo **é obrigatório no teste**: é exatamente ele que expõe a armadilha do
Jackson. Um teste sem esse campo passaria com o bug presente.

Esperado: `HTTP 200` e uma linha nova em `tc_push_subscriptions`. Confira no banco — não na tela.

### Checklist antes de entregar

1. `./gradlew test checkstyleMain` — verde.
2. `npx tsc --noEmit` e `npx eslint <arquivos tocados>` no painel — limpos.
3. `POST /api/push/subscribe` com `expirationTime` → 200 **e linha no banco**.
4. Segundo POST com o **mesmo** endpoint → continua **uma** linha (upsert, não duplicata).
5. POST com o mesmo endpoint autenticado como **outro** usuário → a linha troca de dono, não duplica.
6. `POST /api/push/unsubscribe` → a linha some.
7. Nenhum usuário nem inscrição de teste sobrando: `SELECT COUNT(*) FROM tc_users;` e
   `SELECT COUNT(*) FROM tc_push_subscriptions;` de volta ao valor de antes.
8. Log do Traccar sem exceção nova: `docker logs traccar-rdm --since 10m | grep -iE "error|exception"`.

## Por que tabela e não atributo do usuário

Pergunta levantada em 2026-08-31, decidida contra o atributo. **Registrado aqui para a discussão não
voltar** — a proposta era guardar as inscrições em `tc_users.attributes`, como o
`NotificatorFirebase` do upstream faz com `notificationTokens`, na premissa de que remover um
aparelho ficaria mais fácil.

**A premissa não se sustenta.** Remover é mais simples na tabela:

| Operação | Tabela | Atributo |
|---|---|---|
| Apagar um aparelho | `DELETE WHERE endpoint=? AND userid=?` | ler → parsear → filtrar → serializar → gravar |
| Apagar todos (troca de senha) | `DELETE WHERE userid=?` | idem, e disputando o mesmo campo com o painel |
| Limpar inscrição morta (404/410) | um `DELETE` | idem |

**E o atributo traz um risco medido:**

1. **Teto de ~7 aparelhos, com perda silenciosa.** `tc_users.attributes` é `varchar(4000)`. Uma
   inscrição ocupa ~468 caracteres em JSON puro e ~490 já escapada dentro do atributo — 8 aparelhos
   dão 3939, e isso **sem** as preferências que o painel já grava ali (unidades, fuso, mapa, zoom).
   O golpe é o que acontece ao estourar: a conexão do Traccar usa `sessionVariables=sql_mode=''`, e
   com `sql_mode` vazio **o MySQL trunca em silêncio em vez de dar erro** (verificado: 20 caracteres
   enviados, 10 gravados, nenhum aviso). JSON truncado é JSON inválido — o usuário perderia **todas**
   as preferências, não só o push, e nada denunciaria.
2. **Atualização perdida.** O painel grava `attributes` em Minha conta. Se o envio remover uma
   inscrição morta no mesmo instante em que o usuário salva as preferências, um dos dois some. Com
   linhas independentes isso não existe.
3. **Some a restrição de unicidade.** Hoje `endpoint UNIQUE` impede duplicata e permite a troca de
   dono quando outro usuário loga no mesmo navegador. Num blob, detectar o mesmo endpoint em outra
   conta exigiria varrer os atributos de todos os usuários.
4. **Cache.** Objetos `User` são cacheados; gravar atributo a partir do notificator exigiria
   invalidação, mais um passo para errar.

**O que o atributo teria de bom, com honestidade:** nenhuma consulta extra no envio, já que o `User`
já está carregado. É real, e é o único ponto a favor — não paga os quatro riscos acima.

**O que valia na ideia:** o desejo por trás dela — ver e gerenciar os aparelhos conectados. Isso é
uma funcionalidade, não um modelo de dados, e a tabela já a favorece: `useragent` e `createdat`
existem exatamente para listar "seus aparelhos" com um botão de remover em cada um.

## Referências

- RFC 8030 — Generic Event Delivery Using HTTP Push
- RFC 8188 — Encrypted Content-Encoding for HTTP (`aes128gcm`)
- RFC 8291 — Message Encryption for Web Push (o vetor de teste está na seção 5)
- RFC 8292 — VAPID for Web Push
