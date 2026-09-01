/*
 * Copyright 2026 RDM Rastreamento
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.traccar.helper.model;

import org.traccar.model.AttributeMap;
import org.traccar.model.Notification;
import org.traccar.model.User;
import org.traccar.storage.Storage;
import org.traccar.storage.StorageException;
import org.traccar.storage.query.Columns;
import org.traccar.storage.query.Condition;
import org.traccar.storage.query.Request;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;

/**
 * Notificações padrão: as que todo usuário novo já nasce com elas.
 *
 * <p>O Traccar de origem não tem nada disto — quem cria um usuário precisa entrar em cada conta
 * nova e repetir as mesmas regras à mão (pânico, ignição, bateria). O que faltava, e é o que esta
 * classe resolve, é marcar uma regra como padrão <b>uma vez</b> e o servidor repeti-la sozinho.
 *
 * <p>A marca é um atributo da própria notificação ({@code rdm.autoAssign}), e não uma coluna: não
 * exige migração de schema e não conflita no merge com o upstream.
 *
 * <p><b>Cópia, e não vínculo.</b> Ligar a mesma notificação a vários usuários funcionaria — o
 * Traccar permite —, mas quem recebe o vínculo também recebe permissão de <b>apagar</b> o objeto,
 * e uma exclusão em uma conta qualquer levaria a regra embora de todo mundo, em silêncio. Cada
 * usuário fica com a sua cópia; em troca, editar o padrão depois não alcança quem já foi criado,
 * o que é exatamente o que "adicionar a novos usuários" promete.
 */
public final class NotificationUtil {

    /** Atributo que marca a notificação como padrão para usuários novos. */
    public static final String ATTRIBUTE_AUTO_ASSIGN = "rdm.autoAssign";

    /**
     * Atributo da <b>cópia</b>: esta regra veio da administração. Quem a recebeu pode desligá-la,
     * mas não editar nem excluir — ver {@link #checkEditable}.
     */
    public static final String ATTRIBUTE_MANAGED = "rdm.managed";

    /**
     * Atributo do interruptor: ligado, a regra continua cadastrada e simplesmente <b>não dispara</b>
     * (ver {@code NotificationManager}). É a única coisa que o dono de uma regra da administração
     * pode mudar — desligar sem apagar, para poder religar depois.
     */
    public static final String ATTRIBUTE_DISABLED = "rdm.disabled";

    private NotificationUtil() {
    }

    /**
     * As notificações marcadas como padrão que devem servir de molde para um usuário novo.
     *
     * @param creatorId quem está criando o usuário, ou 0 no auto-cadastro
     */
    public static List<Notification> getDefaults(Storage storage, long creatorId) throws StorageException {
        List<Long> owners;
        if (creatorId > 0) {
            owners = List.of(creatorId);
        } else {
            // Auto-cadastro: não existe criador, então o molde é o de quem administra o servidor.
            owners = storage.getObjects(User.class, new Request(
                            new Columns.Include("id"), new Condition.Equals("administrator", true)))
                    .stream().map(User::getId).toList();
        }

        // Um mesmo objeto pode pertencer a mais de um administrador; o mapa por id evita copiá-lo duas vezes.
        Map<Long, Notification> result = new LinkedHashMap<>();
        for (long ownerId : owners) {
            var notifications = storage.getObjects(Notification.class, new Request(
                    new Columns.All(),
                    new Condition.Permission(User.class, ownerId, Notification.class).excludeGroups()));
            for (Notification notification : notifications) {
                // Regra desligada não vale como padrão: plantá-la já apagada em contas novas só
                // encheria a lista de gente que nunca a viu funcionar.
                if (notification.getBoolean(ATTRIBUTE_AUTO_ASSIGN) && !notification.getBoolean(ATTRIBUTE_DISABLED)) {
                    result.putIfAbsent(notification.getId(), notification);
                }
            }
        }
        return new ArrayList<>(result.values());
    }

    /**
     * Copia a notificação para o usuário e devolve o id da cópia.
     *
     * <p>A cópia não herda a marca de padrão: ela é o resultado da regra, não uma nova regra a ser
     * repetida — se herdasse, quem recebesse a cópia propagaria os padrões alheios ao criar contas.
     * Em lugar dela entra a marca de regra da administração, que é o que trava a edição e a exclusão.
     */
    public static long copyTo(Storage storage, Notification source, long userId) throws StorageException {
        Notification copy = new Notification();
        copy.setType(source.getType());
        copy.setDescription(source.getDescription());
        copy.setAlways(source.getAlways());
        copy.setNotificators(source.getNotificators());
        copy.setCommandId(source.getCommandId());
        copy.setCalendarId(source.getCalendarId());

        AttributeMap attributes = new AttributeMap(source.getAttributes());
        attributes.remove(ATTRIBUTE_AUTO_ASSIGN);
        attributes.put(ATTRIBUTE_MANAGED, true);
        copy.setAttributes(attributes);

        return storage.addObject(copy, new Request(new Columns.Exclude("id")));
    }

    /**
     * Recusa a alteração se ela mexer em regra da administração além do interruptor.
     *
     * <p>Sem esta trava, o "não pode editar" seria só um botão escondido na tela: qualquer cliente
     * com o token na mão mandaria um PUT e trocaria os canais da própria regra padrão. Quem manda é
     * o servidor.
     *
     * @param admin quem está alterando é administrador (passa por cima da trava)
     */
    public static void checkEditable(Notification before, Notification after, boolean admin) {
        if (admin || before == null || !before.getBoolean(ATTRIBUTE_MANAGED)) {
            return;
        }
        if (!onlyToggleChanged(before, after)) {
            throw new SecurityException("Managed notification can only be enabled or disabled");
        }
    }

    /** Recusa a exclusão de regra da administração por quem não administra. */
    public static void checkRemovable(Notification notification, boolean admin) {
        if (!admin && notification != null && notification.getBoolean(ATTRIBUTE_MANAGED)) {
            throw new SecurityException("Managed notification cannot be removed");
        }
    }

    /**
     * Verdadeiro quando as duas versões só diferem no interruptor.
     *
     * <p>Os atributos são comparados pelo texto de cada valor: o mesmo número volta do JSON como
     * {@code Integer} e do banco como {@code Long}, e uma comparação de objetos acusaria mudança
     * onde não houve — o usuário levaria "não pode editar" ao tentar apenas desligar.
     */
    private static boolean onlyToggleChanged(Notification before, Notification after) {
        return Objects.equals(before.getType(), after.getType())
                && Objects.equals(before.getDescription(), after.getDescription())
                && before.getAlways() == after.getAlways()
                && Objects.equals(before.getNotificators(), after.getNotificators())
                && before.getCommandId() == after.getCommandId()
                && before.getCalendarId() == after.getCalendarId()
                && normalize(before).equals(normalize(after));
    }

    private static Map<String, String> normalize(Notification notification) {
        Map<String, String> result = new TreeMap<>();
        notification.getAttributes().forEach((key, value) -> {
            if (!ATTRIBUTE_DISABLED.equals(key)) {
                result.put(key, String.valueOf(value));
            }
        });
        return result;
    }

}
