/*
 * Copyright 2015 - 2026 Anton Tananaev (anton@traccar.org)
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

import com.warrenstrange.googleauth.GoogleAuthenticator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.core.Context;
import org.traccar.api.BaseObjectResource;
import org.traccar.api.security.ServiceAccountUser;
import org.traccar.config.Config;
import org.traccar.config.Keys;
import org.traccar.database.MediaManager;
import org.traccar.helper.LogAction;
import org.traccar.helper.SessionHelper;
import org.traccar.helper.model.NotificationUtil;
import org.traccar.helper.model.UserAvatar;
import org.traccar.helper.model.UserUtil;
import org.traccar.model.Device;
import org.traccar.model.ManagedUser;
import org.traccar.model.Notification;
import org.traccar.model.ObjectOperation;
import org.traccar.model.Permission;
import org.traccar.model.User;
import org.traccar.session.cache.CacheManager;
import org.traccar.storage.StorageException;
import org.traccar.storage.query.Columns;
import org.traccar.storage.query.Condition;
import org.traccar.storage.query.Order;
import org.traccar.storage.query.Request;

import jakarta.annotation.security.PermitAll;
import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.HeaderParam;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.LinkedList;
import java.util.List;
import java.util.stream.Stream;

@Path("users")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public class UserResource extends BaseObjectResource<User> {

    private static final Logger LOGGER = LoggerFactory.getLogger(UserResource.class);

    private static final int DEFAULT_BUFFER_SIZE = 8192;

    /** O mesmo teto da foto de veículo ({@code DeviceResource}). */
    private static final int IMAGE_SIZE_LIMIT = 500000;

    @Inject
    private Config config;

    @Inject
    private MediaManager mediaManager;

    @Inject
    private LogAction actionLogger;

    @Inject
    private CacheManager cacheManager;

    @Context
    private HttpServletRequest request;

    public UserResource() {
        super(User.class);
    }

    @GET
    public Stream<User> get(
            @QueryParam("userId") long userId, @QueryParam("deviceId") long deviceId,
            @QueryParam("excludeAttributes") boolean excludeAttributes,
            @QueryParam("limit") int limit, @QueryParam("offset") int offset,
            @QueryParam("keyword") String keyword) throws StorageException {
        var conditions = new LinkedList<Condition>();
        if (userId > 0) {
            permissionsService.checkUser(getUserId(), userId);
            conditions.add(new Condition.Permission(User.class, userId, ManagedUser.class).excludeGroups());
        } else if (permissionsService.notAdmin(getUserId())) {
            conditions.add(new Condition.Permission(User.class, getUserId(), ManagedUser.class).excludeGroups());
        }
        if (deviceId > 0) {
            permissionsService.checkManager(getUserId());
            permissionsService.checkPermission(Device.class, getUserId(), deviceId);
            conditions.add(new Condition.Permission(User.class, Device.class, deviceId).excludeGroups());
        }
        if (keyword != null && !keyword.isEmpty()) {
            conditions.add(new Condition.Contains(List.of("name", "email"), keyword));
        }
        Columns columns = excludeAttributes ? new Columns.Exclude("attributes") : new Columns.All();
        return storage.getObjectsStream(baseClass, new Request(
                columns, Condition.merge(conditions), new Order("name", false, limit, offset)));
    }

    @Override
    @PermitAll
    @POST
    public Response add(User entity) throws StorageException {
        User currentUser = getUserId() > 0 ? permissionsService.getUser(getUserId()) : null;
        if (currentUser == null || !currentUser.getAdministrator()) {
            permissionsService.checkUserUpdate(getUserId(), new User(), entity);
            if (currentUser != null && currentUser.getUserLimit() != 0) {
                int userLimit = currentUser.getUserLimit();
                if (userLimit > 0) {
                    int userCount = storage.getObjects(baseClass, new Request(
                            new Columns.All(),
                            new Condition.Permission(User.class, getUserId(), ManagedUser.class).excludeGroups()))
                            .size();
                    if (userCount >= userLimit) {
                        throw new SecurityException("Manager user limit reached");
                    }
                }
            } else {
                if (UserUtil.isEmpty(storage)) {
                    entity.setAdministrator(true);
                } else if (!permissionsService.getServer().getRegistration()) {
                    throw new SecurityException("Registration disabled");
                }
                if (permissionsService.getServer().getBoolean(Keys.WEB_TOTP_FORCE.getKey())
                        && entity.getTotpKey() == null) {
                    throw new SecurityException("One-time password key is required");
                }
                UserUtil.setUserDefaults(entity, config);
            }
        }

        entity.setId(storage.addObject(entity, new Request(new Columns.Exclude("id"))));
        storage.updateObject(entity, new Request(
                new Columns.Include("hashedPassword", "salt"),
                new Condition.Equals("id", entity.getId())));

        actionLogger.create(request, getUserId(), entity);

        if (currentUser != null && currentUser.getUserLimit() != 0) {
            storage.addPermission(new Permission(User.class, getUserId(), ManagedUser.class, entity.getId()));
            actionLogger.link(request, getUserId(), User.class, getUserId(), ManagedUser.class, entity.getId());
        }

        copyDefaultNotifications(entity.getId());

        return Response.ok(entity).build();
    }

    /**
     * Repete no usuário recém-criado as notificações marcadas como padrão (ver {@link NotificationUtil}).
     *
     * <p>Nada aqui pode derrubar o cadastro: o usuário já está gravado quando este método roda, e
     * falhar agora devolveria erro para uma conta que <b>existe</b> — quem tentasse de novo esbarraria
     * no e-mail duplicado. Por isso a falha é registrada no log e o cadastro segue.
     */
    private void copyDefaultNotifications(long userId) {
        try {
            // A conta de serviço não é dona de nada: vale como "sem criador", e o molde vem dos administradores.
            long creatorId = getUserId() != ServiceAccountUser.ID ? getUserId() : 0;
            for (Notification notification : NotificationUtil.getDefaults(storage, creatorId)) {
                long id = NotificationUtil.copyTo(storage, notification, userId);
                storage.addPermission(new Permission(User.class, userId, Notification.class, id));
                cacheManager.invalidatePermission(true, User.class, userId, Notification.class, id, true);
                actionLogger.link(request, getUserId(), User.class, userId, Notification.class, id);
            }
        } catch (Exception error) {
            LOGGER.warn("Default notifications copy failed", error);
        }
    }

    @Path("{id}")
    @DELETE
    public Response remove(@PathParam("id") long id) throws Exception {
        // Lido ANTES da exclusão: depois não há mais linha de onde tirar o nome do arquivo.
        User user = storage.getObject(User.class, new Request(
                new Columns.All(), new Condition.Equals("id", id)));

        Response response = super.remove(id);

        /*
         * Acréscimo da RDM: a foto de perfil sai junto com a conta.
         *
         * Sem isto o binário ficava no disco para sempre, e um administrador ainda conseguia
         * baixá-lo pela URL — a autorização em MediaFilter passa para administrador mesmo quando
         * o dono do arquivo não existe mais.
         */
        if (user != null) {
            String avatar = user.getString(UserAvatar.ATTRIBUTE_FILE);
            if (avatar != null && UserAvatar.ownerId(avatar) == id) {
                try {
                    mediaManager.deleteFile(UserAvatar.DIRECTORY, avatar);
                } catch (IOException e) {
                    // A conta já foi embora: falhar aqui devolveria erro para uma exclusão que
                    // deu certo, e quem tentasse de novo esbarraria num usuário inexistente.
                    LOGGER.warn("User avatar delete failed", e);
                }
            }
        }

        if (getUserId() == id) {
            request.getSession().removeAttribute(SessionHelper.USER_ID_KEY);
        }
        return response;
    }

    @Path("totp")
    @PermitAll
    @POST
    public String generateTotpKey() throws StorageException {
        if (!permissionsService.getServer().getBoolean(Keys.WEB_TOTP_ENABLE.getKey())) {
            throw new SecurityException("One-time password is disabled");
        }
        return new GoogleAuthenticator().createCredentials().getKey();
    }


    /**
     * Foto de perfil — envio.
     *
     * <p>Acréscimo da RDM; ver {@link UserAvatar} para o porquê da pasta própria e do nome
     * derivado do id.
     *
     * <p>Ao contrário da foto de veículo, aqui o vínculo é gravado <b>pelo servidor</b>, na mesma
     * chamada. No veículo o cliente precisa de um segundo PUT para escrever o atributo, e uma
     * falha no meio deixa o arquivo no disco sem ninguém apontando para ele. Como o nome do
     * arquivo é derivado do id, o servidor tem tudo o que precisa para fechar sozinho.
     *
     * @return o nome do arquivo, que o painel usa em {@code /api/media/avatars/<nome>}
     */
    @Path("{id}/image")
    @POST
    @Consumes("image/*")
    public Response uploadImage(
            @PathParam("id") long id, File file,
            @HeaderParam(HttpHeaders.CONTENT_TYPE) String type) throws Exception {

        permissionsService.checkUser(getUserId(), id);
        permissionsService.checkEdit(getUserId(), User.class, false, false);

        User user = storage.getObject(User.class, new Request(
                new Columns.All(), new Condition.Equals("id", id)));
        if (user == null) {
            return Response.status(Response.Status.NOT_FOUND).build();
        }

        String extension = UserAvatar.extension(type);
        String name = UserAvatar.fileName(id, extension);

        try (var input = new FileInputStream(file);
                var output = mediaManager.createFileStream(
                        UserAvatar.DIRECTORY, "user-" + id, extension)) {
            long transferred = 0;
            byte[] buffer = new byte[DEFAULT_BUFFER_SIZE];
            int read;
            while ((read = input.read(buffer, 0, buffer.length)) >= 0) {
                output.write(buffer, 0, read);
                transferred += read;
                if (transferred > IMAGE_SIZE_LIMIT) {
                    throw new IllegalArgumentException("Image size limit exceeded");
                }
            }
        }

        user.set(UserAvatar.ATTRIBUTE_FILE, name);
        user.set(UserAvatar.ATTRIBUTE_TIME, String.valueOf(System.currentTimeMillis()));
        storage.updateObject(user, new Request(
                new Columns.Include("attributes"), new Condition.Equals("id", id)));
        cacheManager.invalidateObject(true, User.class, id, ObjectOperation.UPDATE);
        actionLogger.edit(request, getUserId(), user);

        return Response.ok(name).build();
    }

    /**
     * Foto de perfil — remoção.
     *
     * <p>Apaga o arquivo e o vínculo. Limpar só o atributo deixaria o binário baixável por quem
     * guardou a URL, o que não é o que "remover a foto" promete.
     */
    @Path("{id}/image")
    @DELETE
    public Response deleteImage(@PathParam("id") long id) throws Exception {

        permissionsService.checkUser(getUserId(), id);
        permissionsService.checkEdit(getUserId(), User.class, false, false);

        User user = storage.getObject(User.class, new Request(
                new Columns.All(), new Condition.Equals("id", id)));
        if (user == null) {
            return Response.status(Response.Status.NOT_FOUND).build();
        }

        String name = user.getString(UserAvatar.ATTRIBUTE_FILE);
        if (name != null && UserAvatar.ownerId(name) == id) {
            mediaManager.deleteFile(UserAvatar.DIRECTORY, name);
        }

        user.getAttributes().remove(UserAvatar.ATTRIBUTE_FILE);
        user.getAttributes().remove(UserAvatar.ATTRIBUTE_TIME);
        storage.updateObject(user, new Request(
                new Columns.Include("attributes"), new Condition.Equals("id", id)));
        cacheManager.invalidateObject(true, User.class, id, ObjectOperation.UPDATE);
        actionLogger.edit(request, getUserId(), user);

        return Response.noContent().build();
    }

}
