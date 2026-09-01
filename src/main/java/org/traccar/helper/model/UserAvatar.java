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

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Foto de perfil do usuário — o que o Traccar de origem não tem.
 *
 * <p>Ele guarda foto só de <b>veículo</b> ({@code DeviceResource.uploadImage}), e o
 * {@code MediaFilter} libera o download apenas de caminhos cujo primeiro pedaço é o
 * {@code uniqueId} de um dispositivo. Um avatar não tem dispositivo nenhum, então precisa de uma
 * pasta própria dentro do {@code media.path} e de uma regra própria no filtro.
 *
 * <p><b>Por que não guardar a imagem no usuário.</b> {@code tc_users.attributes} é
 * {@code VARCHAR(4000)}, e é onde moram as preferências da conta: uma imagem em base64 ali
 * estouraria a coluna e levaria junto unidades, mapa e as permissões avançadas do painel. O que
 * fica no atributo é só o <b>nome do arquivo</b>.
 *
 * <p>O nome é derivado do id ({@code user-12.jpg}) em vez de sorteado: é ele que diz de quem é a
 * foto na hora de autorizar o download — sem consulta ao banco, e sem um segundo lugar para a
 * ligação arquivo↔dono se perder.
 */
public final class UserAvatar {

    /** Pasta dentro do {@code media.path}. Não colide com {@code uniqueId} de rastreador real. */
    public static final String DIRECTORY = "avatars";

    /** Atributo do usuário com o nome do arquivo ({@code user-12.jpg}). */
    public static final String ATTRIBUTE_FILE = "rdm.avatar";

    /**
     * Momento do último envio, em milissegundos.
     *
     * <p>O arquivo tem nome fixo por conta — trocar a foto reescreve o mesmo caminho, e o navegador
     * continuaria mostrando a antiga do cache. É este número que o painel põe na consulta da URL
     * para forçar a releitura.
     */
    public static final String ATTRIBUTE_TIME = "rdm.avatarTime";

    private static final Pattern FILE_PATTERN = Pattern.compile("user-(\\d+)\\.(jpg|png|gif|webp)");

    private UserAvatar() {
    }

    public static String fileName(long userId, String extension) {
        return "user-" + userId + "." + extension;
    }

    /**
     * De quem é o arquivo, lido do próprio nome.
     *
     * @return o id do dono, ou 0 quando o nome não é de avatar — que é o caso de qualquer tentativa
     *         de sair da pasta ou de baixar outra coisa
     */
    public static long ownerId(String fileName) {
        if (fileName == null) {
            return 0;
        }
        Matcher matcher = FILE_PATTERN.matcher(fileName);
        return matcher.matches() ? Long.parseLong(matcher.group(1)) : 0;
    }

    /** Extensão para o tipo enviado. Os quatro que o Traccar já aceita em foto de veículo. */
    public static String extension(String contentType) {
        return switch (contentType) {
            case "image/jpeg" -> "jpg";
            case "image/png" -> "png";
            case "image/gif" -> "gif";
            case "image/webp" -> "webp";
            default -> throw new IllegalArgumentException("Unsupported image type");
        };
    }

}
