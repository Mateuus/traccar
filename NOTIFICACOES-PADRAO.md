# Notificações padrão para usuários novos

O Traccar de origem não tem nada parecido: cada usuário criado nasce **sem nenhuma** notificação, e
quem administra precisa entrar em conta por conta e repetir as mesmas regras à mão (pânico, ignição,
bateria). O que se esquece de repetir vira um cliente que não recebe aviso nenhum — e ninguém
descobre até o evento acontecer.

Este fork resolve isso com uma marca na própria notificação.

## Como funciona

* A notificação marcada guarda o atributo **`rdm.autoAssign: true`**.
  Atributo, e não coluna: não exige migração de schema e não conflita no merge com o upstream.
* Ao criar um usuário (`POST /api/users`), o servidor procura as notificações marcadas e **copia**
  cada uma para a conta nova, já com a permissão `tc_user_notification`.
* De onde vem o molde:
  * criador autenticado → as notificações **dele**;
  * auto-cadastro (registro aberto) ou conta de serviço → as notificações de **quem é
    administrador**, sem repetir a mesma se dois administradores tiverem o vínculo.
* A cópia **não** herda a marca de padrão; em lugar dela entra `rdm.managed: true`, que é o que
  trava a edição e a exclusão na conta de quem recebeu.
* Regra **desligada** (`rdm.disabled`) não vale como molde: não é copiada.
* Falha ao copiar não derruba o cadastro — o usuário já está gravado, e devolver erro faria a
  segunda tentativa esbarrar em e-mail duplicado. A falha vai para o log
  (`Default notifications copy failed`).

## O que o usuário pode fazer com a regra que recebeu

| Ação | Usuário | Administrador |
| --- | --- | --- |
| Ligar / desligar (`rdm.disabled`) | sim | sim |
| Editar (evento, canais, calendário, atributos) | **não** | sim |
| Excluir | **não** | sim |

Desligada, a regra continua cadastrada e o `NotificationManager` a ignora no despacho — nada de
apagar para calar um aviso e depois não ter como voltar atrás.

A trava está no `NotificationResource` (`update` e `remove`), e não na tela: esconder o botão no
painel não impede um PUT direto na API. `update` aceita a alteração só quando **nada além do
interruptor** mudou — a comparação normaliza os atributos para texto, porque o mesmo número volta do
JSON como `Integer` e do banco como `Long`, e uma comparação crua acusaria edição onde não houve.

## Cópia, e não vínculo

Ligar a **mesma** notificação a vários usuários funcionaria — o Traccar permite —, mas quem recebe o
vínculo também ganha permissão de **apagar** o objeto: uma exclusão em uma conta qualquer levaria a
regra embora de todo mundo, em silêncio. Cada usuário fica com a sua cópia.

O preço: editar o padrão depois **não** alcança quem já foi criado. É exatamente o que a chave
promete — "adicionar a novos usuários".

## Onde está o código

| Arquivo | Papel |
| --- | --- |
| `src/main/java/org/traccar/helper/model/NotificationUtil.java` | a marca, a busca do molde e a cópia |
| `src/main/java/org/traccar/api/resource/UserResource.java` | chama a cópia depois de gravar o usuário |
| `src/main/java/org/traccar/api/resource/NotificationResource.java` | recusa editar/excluir regra da administração |
| `src/main/java/org/traccar/database/NotificationManager.java` | pula a regra desligada no despacho |

No painel (`traccar-nextjs`), a chave aparece em **Configurações → Notificações → O evento**, como
"Adicionar automaticamente a novos usuários", **só para administradores**; a lista marca essas regras
com a etiqueta **padrão**.

Na conta que recebeu a cópia, a linha ganha a etiqueta **da administração**, o menu perde "Editar" e
"Excluir" e ganha "Ligar"/"Desligar", e abrir a regra mostra um resumo somente-leitura com o
interruptor — não um formulário de campos apagados.

## Armadilha

Regra marcada com **"Vale para toda a frota" desligado** chega ao usuário novo sem nenhum veículo
atribuído — e por isso nunca dispara. O painel avisa disso na hora de salvar.
