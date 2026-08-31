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

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Date;
import java.util.Locale;

import org.traccar.api.BaseResource;
import org.traccar.api.signature.TokenManager;
import org.traccar.config.Config;
import org.traccar.config.Keys;
import org.traccar.model.BaseModel;
import org.traccar.model.Device;
import org.traccar.model.Group;
import org.traccar.model.Permission;
import org.traccar.model.User;
import org.traccar.storage.StorageException;
import org.traccar.storage.query.Columns;
import org.traccar.storage.query.Condition;
import org.traccar.storage.query.Request;

import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.DefaultValue;
import jakarta.ws.rs.FormParam;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;

@Path("share")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public class ShareResource extends BaseResource {

    @Inject
    private Config config;

    @Inject
    private TokenManager tokenManager;

    private String share(
            User user, Class<? extends BaseModel> clazz, long id, Date expiration,
            boolean allowCommands, boolean allowReports)
            throws StorageException, GeneralSecurityException, IOException {

        if (permissionsService.getServer().getBoolean(Keys.DEVICE_SHARE_DISABLE.getKey())) {
            throw new SecurityException("Sharing is disabled");
        }
        if (user.getTemporary()) {
            throw new SecurityException("Temporary user");
        }
        if (user.getExpirationTime() != null && user.getExpirationTime().before(expiration)) {
            expiration = user.getExpirationTime();
        }

        BaseModel object = storage.getObject(clazz, new Request(
                new Columns.All(),
                new Condition.And(
                        new Condition.Equals("id", id),
                        new Condition.Permission(User.class, user.getId(), clazz))));

        String shareEmail;
        if (clazz == Device.class) {
            shareEmail = user.getEmail() + ":" + ((Device) object).getUniqueId();
        } else {
            shareEmail = user.getEmail() + ":" + clazz.getSimpleName().toLowerCase(Locale.ROOT) + ":" + object.getId();
        }

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
            share.setName(clazz == Device.class ? ((Device) object).getName() : ((Group) object).getName());
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
             * RDM: o upstream reaproveita o usuario existente SEM tocar nele.
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
        }

        return tokenManager.generateToken(share.getId(), expiration);
    }

    @Path("device")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @POST
    public String shareDevice(
            @FormParam("deviceId") long deviceId,
            @FormParam("expiration") Date expiration,
            // RDM: `true` por omissao para o corpo do upstream continuar valendo igual.
            @FormParam("allowCommands") @DefaultValue("true") boolean allowCommands,
            @FormParam("allowReports") @DefaultValue("true") boolean allowReports)
            throws StorageException, GeneralSecurityException, IOException {
        return share(
                permissionsService.getUser(getUserId()), Device.class, deviceId, expiration,
                allowCommands, allowReports);
    }

    @Path("group")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @POST
    public String shareGroup(
            @FormParam("groupId") long groupId,
            @FormParam("expiration") Date expiration,
            @FormParam("allowCommands") @DefaultValue("true") boolean allowCommands,
            @FormParam("allowReports") @DefaultValue("true") boolean allowReports)
            throws StorageException, GeneralSecurityException, IOException {
        return share(
                permissionsService.getUser(getUserId()), Group.class, groupId, expiration,
                allowCommands, allowReports);
    }

}
