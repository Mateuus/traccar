/*
 * Copyright 2026 Anton Tananaev (anton@traccar.org)
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

import org.traccar.api.BaseResource;
import org.traccar.api.signature.TokenManager;
import org.traccar.config.Config;
import org.traccar.config.Keys;
import org.traccar.model.BaseModel;
import org.traccar.model.Device;
import org.traccar.model.Group;
import org.traccar.model.ObjectOperation;
import org.traccar.model.Permission;
import org.traccar.model.User;
import org.traccar.session.cache.CacheManager;
import org.traccar.storage.StorageException;
import org.traccar.storage.query.Columns;
import org.traccar.storage.query.Condition;
import org.traccar.storage.query.Request;

import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.DefaultValue;
import jakarta.ws.rs.FormParam;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;

@Path("share")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public class ShareResource extends BaseResource {

    @Inject
    private Config config;

    @Inject
    private TokenManager tokenManager;

    @Inject
    private CacheManager cacheManager;

    private String share(
            User user, Class<? extends BaseModel> clazz, long id, Date expiration,
            boolean allowCommands, boolean allowReports, String name) throws Exception {

        if (permissionsService.getServer().getBoolean(Keys.DEVICE_SHARE_DISABLE.getKey())) {
            throw new SecurityException("Sharing is disabled");
        }
        if (user.getTemporary()) {
            throw new SecurityException("Temporary user");
        }
        if (user.getExpirationTime() != null
                && (expiration == null || user.getExpirationTime().before(expiration))) {
            expiration = user.getExpirationTime();
        }

        BaseModel object = storage.getObject(clazz, new Request(
                new Columns.All(),
                new Condition.And(
                        new Condition.Equals("id", id),
                        new Condition.Permission(User.class, user.getId(), clazz))));
        if (object == null) {
            throw new SecurityException("Object not found or no permission");
        }

        String shareEmail = shareEmail(user, object, name);

        User share = storage.getObject(User.class, new Request(
                new Columns.All(), new Condition.Equals("email", shareEmail)));

        /*
         * RDM: quem compartilha ESCOLHE se o link pode mandar comando (bloquear/desbloquear).
         *
         * Os dois portoes de cima continuam valendo e sao teto, nao sugestao: quem nao pode mandar
         * comando nao consegue conceder isso a ninguem, e o administrador pode desligar comando em
         * link compartilhado para a instalacao inteira (web.shareDevice.commands). A escolha da tela
         * so restringe. `allowCommands` chega true quando o cliente nao manda nada, e ai a conta e
         * exatamente a do upstream.
         */
        boolean limitCommands = user.getLimitCommands()
                || !config.getBoolean(Keys.WEB_SHARE_DEVICE_COMMANDS)
                || !allowCommands;
        boolean disableReports = user.getDisableReports()
                || !config.getBoolean(Keys.WEB_SHARE_DEVICE_REPORTS)
                || !allowReports;

        if (share == null) {
            share = new User();
            String objectName = clazz == Device.class
                    ? ((Device) object).getName() : ((Group) object).getName();
            share.setName(name != null && !name.isBlank() ? name.trim() : objectName);
            share.setEmail(shareEmail);
            share.setExpirationTime(expiration);
            share.setTemporary(true);
            share.setReadonly(true);
            share.setLimitCommands(limitCommands);
            share.setDisableReports(disableReports);

            share.setId(storage.addObject(share, new Request(new Columns.Exclude("id"))));

            storage.addPermission(new Permission(User.class, share.getId(), clazz, id));
        } else {
            /*
             * RDM: o upstream reaproveitava o usuario existente SEM tocar nele (e, desde a 6.17,
             * responde 409); aqui o compartilhamento existente e atualizado.
             *
             * O e-mail do compartilhamento e derivado de (dono, veiculo), entao o segundo
             * compartilhamento do mesmo veiculo cai sempre aqui — e, no upstream, com as permissoes
             * congeladas no primeiro. Na pratica: desmarcar "permitir comandos" e compartilhar de
             * novo NAO tirava o comando, e estender o prazo nao adiantava porque o proprio usuario
             * continuava expirando na data antiga. As duas coisas em silencio.
             *
             * A validade passa a ser a do compartilhamento mais recente. Isso encurta um link
             * distribuido antes com prazo maior, e e o comportamento desejado: quem compartilhou
             * mudou de ideia.
             */
            share.setExpirationTime(expiration);
            share.setLimitCommands(limitCommands);
            share.setDisableReports(disableReports);
            storage.updateObject(share, new Request(
                    new Columns.Include("expirationTime", "limitCommands", "disableReports"),
                    new Condition.Equals("id", share.getId())));
            // sessao aberta com este link passa a ver as permissoes novas sem relogar
            cacheManager.invalidateObject(true, User.class, share.getId(), ObjectOperation.UPDATE);
        }

        String token = tokenManager.generateToken(share.getId(), expiration);

        /*
         * RDM: o token fica gravado no proprio compartilhamento.
         *
         * `generateToken` sorteia um id novo a cada chamada, entao regerar na listagem daria um
         * link DIFERENTE a cada vez que a tela abrisse — e quem ja tinha colado o anterior no
         * WhatsApp ficaria sem saber qual e o "atual". Guardado, a lista mostra sempre o mesmo.
         */
        share.set("rdm.shareToken", token);
        storage.updateObject(share, new Request(
                new Columns.Include("attributes"), new Condition.Equals("id", share.getId())));

        return token;
    }

    /*
     * O e-mail do usuario temporario e a CHAVE do compartilhamento. No upstream ela so tem
     * (dono, objeto) — dai existir um unico compartilhamento por veiculo. RDM: com nome, a chave
     * ganha um terceiro pedaco e passam a caber varios ("para o cliente", "para o guincho"), cada
     * um com prazo e permissoes proprios. Sem nome, a chave e exatamente a do upstream. Sempre em
     * minusculas: o User.setEmail do upstream normaliza o que grava (6.18), e a busca precisa
     * bater com o gravado em banco de collation sensivel a caixa.
     */
    private static String shareEmail(User user, BaseModel object, String name) {
        String shareEmail;
        if (object instanceof Device device) {
            shareEmail = user.getEmail() + ":" + device.getUniqueId();
        } else {
            shareEmail = user.getEmail() + ":"
                    + object.getClass().getSimpleName().toLowerCase(Locale.ROOT) + ":" + object.getId();
        }
        if (name != null && !name.isBlank()) {
            shareEmail = shareEmail + ":" + name.trim();
        }
        return shareEmail.trim().toLowerCase(Locale.ROOT);
    }

    @Path("device")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @POST
    public String shareDevice(
            @FormParam("deviceId") long deviceId,
            @FormParam("expiration") Date expiration,
            // RDM: `true` por omissao para o corpo do upstream continuar valendo igual.
            @FormParam("allowCommands") @DefaultValue("true") boolean allowCommands,
            @FormParam("allowReports") @DefaultValue("true") boolean allowReports,
            @FormParam("name") String name) throws Exception {
        return share(
                permissionsService.getUser(getUserId()), Device.class, deviceId, expiration,
                allowCommands, allowReports, name);
    }

    /**
     * RDM: um compartilhamento como a tela precisa ver.
     *
     * DTO proprio e nao o {@code User}: a linha do compartilhamento e um usuario temporario com
     * hash de senha, salt, atributos e mais uma duzia de campos que nao tem por que sair daqui.
     */
    public static class ShareInfo {

        private final long id;
        private final String name;
        private final Date expiration;
        private final boolean allowCommands;
        private final boolean allowReports;
        private final String token;

        ShareInfo(User share) {
            id = share.getId();
            name = share.getName();
            expiration = share.getExpirationTime();
            allowCommands = !share.getLimitCommands();
            allowReports = !share.getDisableReports();
            token = share.getString("rdm.shareToken");
        }

        public long getId() {
            return id;
        }

        public String getName() {
            return name;
        }

        public Date getExpiration() {
            return expiration;
        }

        public boolean getAllowCommands() {
            return allowCommands;
        }

        public boolean getAllowReports() {
            return allowReports;
        }

        /** Nulo em compartilhamento criado antes desta versao — a tela oferece gerar de novo. */
        public String getToken() {
            return token;
        }
    }

    /**
     * RDM: os compartilhamentos QUE ESTE USUARIO criou para um veiculo.
     *
     * Existe porque {@code GET /api/users?deviceId=} — o caminho que o painel oficial usaria —
     * exige {@code checkManager}, e compartilhar nao exige. Sem isto, um usuario comum criaria
     * links e nunca mais os veria para revogar.
     *
     * O recorte de dono e o prefixo do e-mail, que e como o proprio upstream identifica o
     * compartilhamento: ninguem enxerga link de outra conta, nem administrador.
     */
    @Path("device")
    @GET
    public List<ShareInfo> getDeviceShares(@QueryParam("deviceId") long deviceId) throws StorageException {
        User user = permissionsService.getUser(getUserId());
        permissionsService.checkPermission(Device.class, getUserId(), deviceId);
        String prefix = user.getEmail() + ":";
        var shares = new ArrayList<ShareInfo>();
        for (User candidate : storage.getObjects(User.class, new Request(
                new Columns.All(), new Condition.Permission(User.class, Device.class, deviceId)))) {
            if (candidate.getTemporary() && candidate.getEmail() != null
                    && candidate.getEmail().startsWith(prefix)) {
                shares.add(new ShareInfo(candidate));
            }
        }
        return shares;
    }

    /**
     * RDM: revoga um compartilhamento apagando o usuario temporario dele.
     *
     * Apagar o usuario derruba o link na hora — o token aponta para um id que deixou de existir.
     * O {@code DELETE /api/users/{id}} do upstream nao serve: quem compartilha nao e gestor do
     * usuario temporario que o servidor criou, entao a permissao seria negada.
     */
    @Path("{id}")
    @DELETE
    public Response deleteShare(@PathParam("id") long id) throws Exception {
        User user = permissionsService.getUser(getUserId());
        User share = storage.getObject(User.class, new Request(
                new Columns.All(), new Condition.Equals("id", id)));
        if (share == null || !share.getTemporary()
                || share.getEmail() == null || !share.getEmail().startsWith(user.getEmail() + ":")) {
            throw new SecurityException("Not a share of this user");
        }
        storage.removeObject(User.class, new Request(new Condition.Equals("id", id)));
        cacheManager.invalidateObject(true, User.class, id, ObjectOperation.DELETE);
        return Response.noContent().build();
    }

    /*
     * Rotas do upstream (6.17+): revogam o compartilhamento SEM nome do objeto, que e o unico que
     * o painel oficial cria. Mesma regra de dono do DELETE /share/{id}; o painel da RDM usa aquele.
     */
    private Response removeDefaultShare(Class<? extends BaseModel> clazz, long objectId) throws Exception {
        User user = permissionsService.getUser(getUserId());
        BaseModel object = storage.getObject(clazz, new Request(
                new Columns.All(),
                new Condition.And(
                        new Condition.Equals("id", objectId),
                        new Condition.Permission(User.class, user.getId(), clazz))));
        if (object == null) {
            throw new SecurityException("Object not found or no permission");
        }
        User share = storage.getObject(User.class, new Request(
                new Columns.All(), new Condition.Equals("email", shareEmail(user, object, null))));
        if (share == null || !share.getTemporary()) {
            throw new WebApplicationException(Response.Status.NOT_FOUND);
        }
        return deleteShare(share.getId());
    }

    @Path("device/{id}")
    @DELETE
    public Response removeDeviceShare(@PathParam("id") long deviceId) throws Exception {
        return removeDefaultShare(Device.class, deviceId);
    }

    @Path("group/{id}")
    @DELETE
    public Response removeGroupShare(@PathParam("id") long groupId) throws Exception {
        return removeDefaultShare(Group.class, groupId);
    }

    @Path("group")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @POST
    public String shareGroup(
            @FormParam("groupId") long groupId,
            @FormParam("expiration") Date expiration,
            @FormParam("allowCommands") @DefaultValue("true") boolean allowCommands,
            @FormParam("allowReports") @DefaultValue("true") boolean allowReports,
            @FormParam("name") String name) throws Exception {
        return share(
                permissionsService.getUser(getUserId()), Group.class, groupId, expiration,
                allowCommands, allowReports, name);
    }

}
