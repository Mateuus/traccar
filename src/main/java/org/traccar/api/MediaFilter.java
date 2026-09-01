/*
 * Copyright 2018 - 2025 Anton Tananaev (anton@traccar.org)
 * Copyright 2018 Andrey Kunitsyn (andrey@traccar.org)
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
package org.traccar.api;

import com.google.inject.Provider;
import org.traccar.api.security.PermissionsService;
import org.traccar.database.StatisticsManager;
import org.traccar.helper.SessionHelper;
import org.traccar.helper.model.UserAvatar;
import org.traccar.model.Device;
import org.traccar.storage.Storage;
import org.traccar.storage.StorageException;
import org.traccar.storage.query.Columns;
import org.traccar.storage.query.Condition;
import org.traccar.storage.query.Request;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import java.io.IOException;

@Singleton
public class MediaFilter implements Filter {

    private final Storage storage;
    private final StatisticsManager statisticsManager;
    private final Provider<PermissionsService> permissionsServiceProvider;

    @Inject
    public MediaFilter(
            Storage storage, StatisticsManager statisticsManager,
            Provider<PermissionsService> permissionsServiceProvider) {
        this.storage = storage;
        this.statisticsManager = statisticsManager;
        this.permissionsServiceProvider = permissionsServiceProvider;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        HttpServletResponse httpResponse = (HttpServletResponse) response;
        try {
            Long userId = null;
            if (SessionHelper.isSessionOriginValid((HttpServletRequest) request)) {
                HttpSession session = ((HttpServletRequest) request).getSession(false);
                userId = (Long) session.getAttribute(SessionHelper.USER_ID_KEY);
                if (userId != null) {
                    statisticsManager.registerRequest(userId);
                }
            }
            if (userId == null) {
                httpResponse.sendError(HttpServletResponse.SC_UNAUTHORIZED);
                return;
            }

            String path = ((HttpServletRequest) request).getPathInfo();
            String[] parts = path != null ? path.split("/") : null;
            if (parts != null && parts.length >= 2) {
                /*
                 * Acréscimo da RDM: a pasta de avatares (ver UserAvatar). O primeiro pedaço do
                 * caminho aqui é sempre o uniqueId de um dispositivo, e um avatar não tem
                 * dispositivo — sem esta regra, toda foto de perfil responderia 403.
                 *
                 * De quem é a foto sai do próprio nome do arquivo, então autorizar é a mesma
                 * pergunta de "posso ver esta conta?": ela mesma, um administrador, ou o gerente
                 * dela. Nome fora do formato devolve dono 0, que não é conta de ninguém e cai no
                 * 403 abaixo.
                 */
                if (UserAvatar.DIRECTORY.equals(parts[1])) {
                    long ownerId = parts.length >= 3 ? UserAvatar.ownerId(parts[2]) : 0;
                    if (ownerId > 0) {
                        permissionsServiceProvider.get().checkUser(userId, ownerId);
                        chain.doFilter(request, response);
                        return;
                    }
                } else {
                    Device device = storage.getObject(Device.class, new Request(
                            new Columns.All(), new Condition.Equals("uniqueId", parts[1])));
                    if (device != null) {
                        permissionsServiceProvider.get().checkPermission(Device.class, userId, device.getId());
                        chain.doFilter(request, response);
                        return;
                    }
                }
            }

            httpResponse.sendError(HttpServletResponse.SC_FORBIDDEN);
        } catch (SecurityException | StorageException e) {
            httpResponse.setStatus(HttpServletResponse.SC_FORBIDDEN);
            e.printStackTrace(httpResponse.getWriter());
        }
    }

}
