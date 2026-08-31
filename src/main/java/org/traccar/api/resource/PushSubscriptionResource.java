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
package org.traccar.api.resource;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.HeaderParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.traccar.api.BaseResource;
import org.traccar.model.PushSubscription;
import org.traccar.notificators.NotificatorWebPush;
import org.traccar.storage.StorageException;
import org.traccar.storage.query.Columns;
import org.traccar.storage.query.Condition;
import org.traccar.storage.query.Order;
import org.traccar.storage.query.Request;

import java.util.Date;
import java.util.List;
import java.util.Map;

/**
 * Inscricoes de Web Push do navegador.
 *
 * O fluxo do lado do cliente e: pedir a chave publica aqui, chamar {@code pushManager.subscribe()}
 * com ela e devolver a inscricao resultante para {@code subscribe}. A inscricao pertence ao usuario
 * autenticado no momento do POST — e por isso que o logout precisa chamar {@code unsubscribe}: sem
 * isso, o proximo usuario daquele navegador herdaria os alertas do anterior.
 */
@Path("push")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public class PushSubscriptionResource extends BaseResource {

    @Inject
    private NotificatorWebPush notificator;

    /**
     * Espelha o JSON de {@code PushSubscription.toJSON()} do navegador.
     *
     * ⚠️ O {@code ignoreUnknown} NAO e enfeite. O navegador serializa TRES campos —
     * {@code endpoint}, {@code keys} e {@code expirationTime} — e o ObjectMapper do Traccar nao
     * desliga {@code FAIL_ON_UNKNOWN_PROPERTIES} (ver {@code MainModule.provideObjectMapper}).
     * Sem esta anotacao, o {@code expirationTime} sozinho faz o Jackson recusar o corpo inteiro
     * com 400, e o sintoma e cruel: o navegador se inscreve com sucesso, a tela diz "alertas
     * ativos" (porque so consulta o navegador), o servidor nunca grava nada e nenhum push chega.
     * Os modelos do upstream que recebem JSON de fora — {@code Command}, {@code Server} — carregam
     * a mesma anotacao pelo mesmo motivo.
     */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class SubscriptionRequest {
        @JsonProperty("endpoint")
        private String endpoint;
        @JsonProperty("keys")
        private Map<String, String> keys;

        public String getEndpoint() {
            return endpoint;
        }

        public Map<String, String> getKeys() {
            return keys;
        }
    }

    /**
     * O que a tela "Aparelhos que recebem alertas" precisa saber de cada inscricao.
     *
     * DTO proprio, e nao a entidade: {@code publicKey} e {@code authSecret} sao material de
     * cifragem e nao tem razao nenhuma para sair do servidor. Devolver o {@link PushSubscription}
     * e confiar numa anotacao de exclusao funcionaria hoje, mas o dia em que alguem acrescentar um
     * campo sensivel na entidade ele vaza sozinho, sem ninguem notar. Aqui o vazamento exigiria
     * escrever o getter de proposito.
     */
    public static class SubscriptionInfo {

        private final long id;
        private final String endpoint;
        private final String userAgent;
        private final Date createdAt;

        SubscriptionInfo(PushSubscription subscription) {
            id = subscription.getId();
            endpoint = subscription.getEndpoint();
            userAgent = subscription.getUserAgent();
            createdAt = subscription.getCreatedAt();
        }

        public long getId() {
            return id;
        }

        /**
         * O endpoint sai porque e a identidade da inscricao: e por ele que o painel reconhece qual
         * linha e o aparelho de quem esta olhando, e e ele que volta no {@code unsubscribe}.
         */
        public String getEndpoint() {
            return endpoint;
        }

        public String getUserAgent() {
            return userAgent;
        }

        public Date getCreatedAt() {
            return createdAt;
        }
    }

    /**
     * As inscricoes do usuario autenticado, das mais novas para as mais velhas.
     *
     * Sem nenhuma nocao de administrador de proposito: isto responde "quais aparelhos MEUS recebem
     * alerta", e nao existe caso de uso para um usuario ver o parque de aparelhos de outro. Quem
     * precisar auditar tem o banco.
     */
    @Path("subscriptions")
    @GET
    public List<SubscriptionInfo> subscriptions() throws StorageException {
        /*
         * Include e nao All: assim as chaves de cifragem nem chegam a sair do banco. O JSON sairia
         * igual filtrando depois em Java, mas nao ha por que carregar segredo na memoria da JVM
         * para em seguida jogar fora.
         */
        List<PushSubscription> subscriptions = storage.getObjects(PushSubscription.class, new Request(
                new Columns.Include("id", "endpoint", "userAgent", "createdAt"),
                new Condition.Equals("userId", getUserId()),
                new Order("createdAt", true, 0)));
        return subscriptions.stream().map(SubscriptionInfo::new).toList();
    }

    @Path("publicKey")
    @GET
    public Response publicKey() {
        String key = notificator.getPublicKey();
        if (key == null) {
            // 503 e nao 404: a rota existe, o servidor e que esta sem par VAPID configurado.
            return Response.status(Response.Status.SERVICE_UNAVAILABLE)
                    .entity(Map.of("error", "web push is not configured")).build();
        }
        return Response.ok(Map.of("publicKey", key)).build();
    }

    @Path("subscribe")
    @POST
    public Response subscribe(
            SubscriptionRequest body, @HeaderParam("User-Agent") String userAgent) throws StorageException {

        if (body == null || body.getEndpoint() == null || body.getKeys() == null) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of("error", "endpoint and keys are required")).build();
        }
        String p256dh = body.getKeys().get("p256dh");
        String auth = body.getKeys().get("auth");
        if (p256dh == null || auth == null) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of("error", "keys must contain p256dh and auth")).build();
        }

        PushSubscription existing = storage.getObject(PushSubscription.class, new Request(
                new Columns.All(), new Condition.Equals("endpoint", body.getEndpoint())));

        if (existing != null) {
            /*
             * Mesmo endpoint ja gravado. Pode ser o mesmo usuario reabrindo o painel (nada muda) ou
             * OUTRO usuario no mesmo navegador — e ai a linha tem de trocar de dono, nunca duplicar:
             * o endpoint e unico e a chave de cifragem pode ter sido renovada pelo navegador.
             */
            existing.setUserId(getUserId());
            existing.setPublicKey(p256dh);
            existing.setAuthSecret(auth);
            existing.setUserAgent(truncate(userAgent));
            storage.updateObject(existing, new Request(
                    new Columns.Exclude("id"), new Condition.Equals("id", existing.getId())));
            return Response.ok(Map.of("id", existing.getId())).build();
        }

        PushSubscription subscription = new PushSubscription();
        subscription.setUserId(getUserId());
        subscription.setEndpoint(body.getEndpoint());
        subscription.setPublicKey(p256dh);
        subscription.setAuthSecret(auth);
        subscription.setUserAgent(truncate(userAgent));
        subscription.setCreatedAt(new Date());
        subscription.setId(storage.addObject(subscription, new Request(new Columns.Exclude("id"))));
        return Response.ok(Map.of("id", subscription.getId())).build();
    }

    @Path("unsubscribe")
    @POST
    public Response unsubscribe(SubscriptionRequest body) throws StorageException {
        if (body == null || body.getEndpoint() == null) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of("error", "endpoint is required")).build();
        }
        /*
         * Apaga pelo par (endpoint, usuario). So por endpoint deixaria um usuario derrubar a
         * inscricao de outro conhecendo a URL; so por usuario derrubaria os outros aparelhos dele.
         */
        storage.removeObject(PushSubscription.class, new Request(Condition.merge(List.of(
                new Condition.Equals("endpoint", body.getEndpoint()),
                new Condition.Equals("userId", getUserId())))));
        return Response.noContent().build();
    }

    /** A coluna tem 255; um User-Agent exotico maior que isso nao pode derrubar a inscricao. */
    private String truncate(String userAgent) {
        if (userAgent == null) {
            return null;
        }
        return userAgent.length() > 255 ? userAgent.substring(0, 255) : userAgent;
    }

}
