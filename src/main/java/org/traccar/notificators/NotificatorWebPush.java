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
package org.traccar.notificators;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import jakarta.ws.rs.client.Client;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.Variant;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.traccar.config.Config;
import org.traccar.config.Keys;
import org.traccar.helper.WebHelper;
import org.traccar.model.Event;
import org.traccar.model.Position;
import org.traccar.model.PushSubscription;
import org.traccar.model.User;
import org.traccar.notification.NotificationFormatter;
import org.traccar.notification.NotificationMessage;
import org.traccar.notificators.webpush.VapidSigner;
import org.traccar.notificators.webpush.WebPushEncryption;
import org.traccar.notificators.webpush.WebPushKeys;
import org.traccar.storage.Storage;
import org.traccar.storage.StorageException;
import org.traccar.storage.query.Columns;
import org.traccar.storage.query.Condition;
import org.traccar.storage.query.Request;

import java.security.interfaces.ECPrivateKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.CompletableFuture;

/**
 * Web Push (RFC 8291) para o navegador — o canal "webpush".
 *
 * Diferenca essencial para o canal "web": aquele entrega o evento pelo WebSocket, entao so alcanca
 * quem esta com o painel aberto na frente. Este entrega ao push service do navegador (Apple,
 * Google, Mozilla), que acorda o service worker mesmo com o app fechado.
 *
 * Nao substitui o "web": os dois convivem. O "web" continua sendo o caminho de menor latencia para
 * quem esta olhando o mapa; este e o que alcanca o celular no bolso.
 */
@Singleton
public class NotificatorWebPush extends Notificator {

    private static final Logger LOGGER = LoggerFactory.getLogger(NotificatorWebPush.class);

    /**
     * Respostas que significam "esta inscricao morreu". O 404 e o 410 sao a forma padronizada do
     * push service dizer que o navegador desinstalou o app, limpou os dados ou teve a inscricao
     * revogada. Guardar essas linhas so faz o envio seguinte gastar uma requisicao para nada.
     */
    private static final int STATUS_NOT_FOUND = 404;
    private static final int STATUS_GONE = 410;

    private final Client client;
    private final Storage storage;
    private final ObjectMapper objectMapper;

    private final String subject;
    private final int ttl;
    private final ECPrivateKey privateKey;
    private final byte[] publicKey;

    /**
     * Corpo entregue ao service worker. Campos privados de proposito: o checkstyle proibe campo
     * visivel, e o Jackson serializa pela anotacao de qualquer forma.
     */
    public static class Payload {
        @JsonProperty("title")
        private String title;
        @JsonProperty("body")
        private String body;
        @JsonProperty("tag")
        private String tag;
        @JsonProperty("eventId")
        private long eventId;
        @JsonProperty("deviceId")
        private long deviceId;
        @JsonProperty("type")
        private String type;
    }

    @Inject
    public NotificatorWebPush(
            Config config, NotificationFormatter notificationFormatter, Client client,
            Storage storage, ObjectMapper objectMapper) {
        super(notificationFormatter);
        this.client = client;
        this.storage = storage;
        this.objectMapper = objectMapper;
        this.subject = config.getString(Keys.NOTIFICATOR_WEBPUSH_SUBJECT);
        this.ttl = config.getInteger(Keys.NOTIFICATOR_WEBPUSH_TTL);

        String configuredPublic = config.getString(Keys.NOTIFICATOR_WEBPUSH_PUBLIC_KEY);
        String configuredPrivate = config.getString(Keys.NOTIFICATOR_WEBPUSH_PRIVATE_KEY);

        ECPrivateKey parsedPrivate = null;
        byte[] parsedPublic = null;
        if (configuredPublic != null && configuredPrivate != null) {
            try {
                parsedPublic = WebPushKeys.decodeBase64(configuredPublic);
                parsedPrivate = WebPushKeys.decodePrivateKey(WebPushKeys.decodeBase64(configuredPrivate));
            } catch (Exception e) {
                LOGGER.error("Invalid VAPID key pair, web push disabled", e);
                parsedPublic = null;
                parsedPrivate = null;
            }
        } else {
            LOGGER.error("Notificator webpush is enabled but VAPID keys are missing");
        }
        this.publicKey = parsedPublic;
        this.privateKey = parsedPrivate;
    }

    /** A chave publica que o navegador precisa usar ao se inscrever. Null enquanto nao configurada. */
    public String getPublicKey() {
        return publicKey != null ? WebPushKeys.encodeBase64(publicKey) : null;
    }

    @Override
    public CompletableFuture<Void> sendAsync(
            User user, NotificationMessage message, Event event, Position position) {

        if (privateKey == null) {
            return CompletableFuture.failedFuture(
                    new IllegalStateException("Web push is not configured (missing VAPID keys)"));
        }

        List<PushSubscription> subscriptions;
        try {
            subscriptions = storage.getObjects(PushSubscription.class, new Request(
                    new Columns.All(), new Condition.Equals("userId", user.getId())));
        } catch (StorageException e) {
            return CompletableFuture.failedFuture(e);
        }
        if (subscriptions.isEmpty()) {
            return CompletableFuture.completedFuture(null);
        }

        byte[] payload;
        try {
            payload = objectMapper.writeValueAsBytes(buildPayload(message, event));
        } catch (Exception e) {
            return CompletableFuture.failedFuture(e);
        }

        List<CompletableFuture<Void>> deliveries = new ArrayList<>(subscriptions.size());
        for (PushSubscription subscription : subscriptions) {
            deliveries.add(deliver(subscription, payload));
        }
        return CompletableFuture.allOf(deliveries.toArray(new CompletableFuture[0]));
    }

    private Payload buildPayload(NotificationMessage message, Event event) {
        Payload payload = new Payload();
        payload.title = message.subject();
        payload.body = message.digest();
        if (event != null) {
            payload.eventId = event.getId();
            payload.deviceId = event.getDeviceId();
            payload.type = event.getType();
            // Uma "tag" por dispositivo faz o alerta seguinte SUBSTITUIR o anterior daquele veiculo,
            // em vez de empilhar. Sem isso um carro com ignicao instavel enche a barra sozinho.
            payload.tag = "device-" + event.getDeviceId();
        }
        return payload;
    }

    private CompletableFuture<Void> deliver(PushSubscription subscription, byte[] payload) {
        byte[] body;
        String authorization;
        try {
            body = WebPushEncryption.encrypt(
                    payload,
                    WebPushKeys.decodeBase64(subscription.getPublicKey()),
                    WebPushKeys.decodeBase64(subscription.getAuthSecret()));
            authorization = VapidSigner.authorization(
                    subscription.getEndpoint(), subject, privateKey, publicKey);
        } catch (Exception e) {
            return CompletableFuture.failedFuture(e);
        }

        var request = client.target(subscription.getEndpoint()).request()
                .header("Authorization", authorization)
                .header("TTL", ttl)
                .header("Urgency", "high");

        /*
         * O Content-Encoding vai pela Variant da entidade, NAO por .header(...).
         *
         * Custou uma investigacao inteira: Content-Encoding e cabecalho de ENTIDADE, e o Jersey
         * reescreve os cabecalhos de entidade a partir da Entity na hora de serializar o corpo.
         * Um .header("Content-Encoding", ...) posto no Invocation.Builder e apagado em silencio —
         * sem excecao, sem log, sem nada na resposta.
         *
         * O sintoma nao aponta para ca em momento nenhum: o push serve o corpo cifrado sem dizer
         * como decifra-lo, o push service ACEITA (200/201, nenhum erro para o log) e o navegador
         * entrega o evento ao service worker com `event.data` NULO. A notificacao aparece, mas com
         * o texto generico de fallback do worker e sem `tag` — dai tambem as dezenas de alertas
         * empilhados em vez de um por veiculo.
         */
        return WebHelper.post(
                request,
                Entity.entity(body, new Variant(MediaType.APPLICATION_OCTET_STREAM_TYPE, (Locale) null, "aes128gcm")),
                response -> handleResponse(subscription, response));
    }

    private void handleResponse(PushSubscription subscription, Response response) {
        int status = response.getStatus();
        if (status == STATUS_NOT_FOUND || status == STATUS_GONE) {
            try {
                storage.removeObject(PushSubscription.class, new Request(
                        new Condition.Equals("id", subscription.getId())));
                LOGGER.info("Removed expired push subscription {}", subscription.getId());
            } catch (StorageException e) {
                LOGGER.warn("Failed to remove expired push subscription {}", subscription.getId(), e);
            }
        } else if (status < 200 || status >= 300) {
            LOGGER.warn("Web push delivery failed with status {} for subscription {}",
                    status, subscription.getId());
        }
    }

}
