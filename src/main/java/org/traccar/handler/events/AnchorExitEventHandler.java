/*
 * Copyright 2025 - RDM Systems
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
package org.traccar.handler.events;

import jakarta.inject.Inject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.traccar.config.Config;
import org.traccar.config.Keys;
import org.traccar.database.CommandsManager;
import org.traccar.helper.model.PositionUtil;
import org.traccar.model.Command;
import org.traccar.model.Event;
import org.traccar.model.Geofence;
import org.traccar.model.Position;
import org.traccar.session.cache.CacheManager;
import org.traccar.storage.Storage;
import org.traccar.storage.StorageException;
import org.traccar.storage.query.Condition;
import org.traccar.storage.query.Request;

import java.util.ArrayList;
import java.util.List;

/**
 * Handler para bloquear dispositivos automaticamente quando saem de âncoras.
 * Identifica âncoras através dos atributos: isAnchor=true e deviceId.
 */
public class AnchorExitEventHandler extends BaseEventHandler {

    private static final Logger LOGGER = LoggerFactory.getLogger(AnchorExitEventHandler.class);

    private final CacheManager cacheManager;
    private final CommandsManager commandsManager;
    private final Storage storage;
    private final boolean enabled;
    private final boolean destroyGeofence;

    @Inject
    public AnchorExitEventHandler(
            Config config,
            CacheManager cacheManager,
            CommandsManager commandsManager,
            Storage storage) {
        this.cacheManager = cacheManager;
        this.commandsManager = commandsManager;
        this.storage = storage;
        this.enabled = config.getBoolean(Keys.EVENT_ANCHOR_EXIT_ENABLED);
        this.destroyGeofence = config.getBoolean(Keys.EVENT_ANCHOR_EXIT_DESTROY_GEOFENCE);
    }

    @Override
    public void onPosition(Position position, Callback callback) {
        if (!enabled || !PositionUtil.isLatest(cacheManager, position)) {
            return;
        }

        // Obter geofences da posição anterior
        List<Long> oldGeofences = new ArrayList<>();
        Position lastPosition = cacheManager.getPosition(position.getDeviceId());
        if (lastPosition != null && lastPosition.getGeofenceIds() != null) {
            oldGeofences.addAll(lastPosition.getGeofenceIds());
        }

        // Obter geofences da posição atual
        List<Long> currentGeofences = new ArrayList<>();
        if (position.getGeofenceIds() != null) {
            currentGeofences.addAll(position.getGeofenceIds());
        }

        // Encontrar geofences que o dispositivo saiu
        List<Long> exitedGeofences = new ArrayList<>(oldGeofences);
        exitedGeofences.removeAll(currentGeofences);

        // Verificar se alguma das geofences é uma âncora
        for (long geofenceId : exitedGeofences) {
            Geofence geofence = cacheManager.getObject(Geofence.class, geofenceId);
            if (geofence != null && isAnchorGeofence(geofence, position.getDeviceId())) {
                handleAnchorExit(position, geofence, callback);
            }
        }
    }

    /**
     * Verifica se uma geofence é uma âncora para o dispositivo específico.
     */
    private boolean isAnchorGeofence(Geofence geofence, long deviceId) {
        // Verificar se tem o atributo isAnchor = true
        boolean isAnchor = geofence.getBoolean("isAnchor");
        if (!isAnchor) {
            return false;
        }

        // Verificar se o deviceId corresponde
        long geofenceDeviceId = geofence.getLong("deviceId");
        return geofenceDeviceId == deviceId;
    }

    /**
     * Trata a saída do dispositivo de uma âncora.
     */
    private void handleAnchorExit(Position position, Geofence geofence, Callback callback) {
        try {
            // O comando é uma tentativa isolada: falha sempre que o dispositivo está offline,
            // que é justamente o cenário de furto. A auditoria não pode depender dele.
            boolean blocked = sendStopCommand(position.getDeviceId());

            // Criar evento para auditoria
            Event event = new Event(Event.TYPE_ANCHOR_EXIT_BLOCK, position);
            event.setGeofenceId(geofence.getId());
            event.set("geofenceName", geofence.getName());
            event.set("blocked", blocked);
            callback.eventDetected(event);

            if (blocked) {
                LOGGER.info("Dispositivo {} bloqueado por sair da âncora: {}",
                        position.getDeviceId(), geofence.getName());
            } else {
                LOGGER.warn("Dispositivo {} saiu da âncora {}, mas o bloqueio NÃO foi enviado",
                        position.getDeviceId(), geofence.getName());
            }

            // Só consome a âncora quando o bloqueio saiu de fato; se falhou, ela permanece
            // armada para uma nova tentativa e visível para o operador.
            if (destroyGeofence && blocked) {
                destroyAnchorGeofence(geofence);
            }

        } catch (Exception e) {
            LOGGER.error("Erro ao tratar saída de âncora", e);
        }
    }

    /**
     * Envia comando engineStop para o dispositivo. Retorna false se o envio falhar.
     */
    private boolean sendStopCommand(long deviceId) {
        Command command = new Command();
        command.setDeviceId(deviceId);
        command.setType(Command.TYPE_ENGINE_STOP);
        command.set(Command.KEY_NO_QUEUE, true);
        try {
            commandsManager.sendCommand(command);
            return true;
        } catch (Exception e) {
            LOGGER.error("Falha ao enviar bloqueio para o dispositivo {}: {}", deviceId, e.getMessage());
            return false;
        }
    }

    /**
     * Remove a geofence âncora do sistema.
     */
    private void destroyAnchorGeofence(Geofence geofence) {
        try {
            storage.removeObject(Geofence.class, new Request(
                    new Condition.Equals("id", geofence.getId())));

            LOGGER.info("Geofence âncora {} removida para evitar falsos positivos",
                    geofence.getName());

        } catch (StorageException e) {
            LOGGER.error("Erro ao remover geofence âncora", e);
        }
    }
}

