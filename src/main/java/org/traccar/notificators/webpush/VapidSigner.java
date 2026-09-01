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
package org.traccar.notificators.webpush;

import java.math.BigInteger;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.Signature;
import java.security.interfaces.ECPrivateKey;
import java.time.Instant;
import java.util.Arrays;

/**
 * Cabecalho Authorization do VAPID (RFC 8292).
 *
 * O push service so aceita a entrega se o JWT ES256 vier assinado pela chave privada que casa com
 * a chave publica usada pelo navegador na inscricao. Trocar o par sem re-inscrever os clientes
 * derruba TODAS as entregas com 403 — por isso a chave publica e servida pela API, e nao embutida
 * no front.
 */
public final class VapidSigner {

    /**
     * Validade do token. O RFC 8292 permite ate 24 h; ficamos na metade para tolerar relogio
     * adiantado no push service sem precisar de sincronia fina.
     */
    private static final long EXPIRATION_SECONDS = 12 * 60 * 60;

    private static final String HEADER_JSON = "{\"typ\":\"JWT\",\"alg\":\"ES256\"}";

    private VapidSigner() {
    }

    /**
     * Monta o valor do cabecalho {@code Authorization} para um endpoint.
     *
     * @param endpoint   endpoint da inscricao (so o origin entra no token)
     * @param subject    contato do responsavel pelo servidor: {@code mailto:} ou {@code https:}
     * @param privateKey chave privada VAPID
     * @param publicKey  chave publica VAPID, 65 bytes
     */
    public static String authorization(String endpoint, String subject, ECPrivateKey privateKey, byte[] publicKey)
            throws GeneralSecurityException {

        URI uri = URI.create(endpoint);
        String audience = uri.getScheme() + "://" + uri.getAuthority();
        long expiration = Instant.now().getEpochSecond() + EXPIRATION_SECONDS;

        String claims = "{\"aud\":\"" + audience + "\",\"exp\":" + expiration + ",\"sub\":\"" + subject + "\"}";
        String signingInput = encode(HEADER_JSON) + "." + encode(claims);

        Signature signature = Signature.getInstance("SHA256withECDSA");
        signature.initSign(privateKey);
        signature.update(signingInput.getBytes(StandardCharsets.US_ASCII));
        String token = signingInput + "." + WebPushKeys.encodeBase64(toJoseSignature(signature.sign()));

        return "vapid t=" + token + ", k=" + WebPushKeys.encodeBase64(publicKey);
    }

    private static String encode(String json) {
        return WebPushKeys.encodeBase64(json.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Converte a assinatura ECDSA de DER para o formato cru do JOSE.
     *
     * O JCE devolve {@code SEQUENCE { INTEGER r, INTEGER s }}, com tamanho variavel: o DER corta
     * zeros a esquerda e insere um 0x00 quando o valor pareceria negativo. O JWS quer exatamente
     * 64 bytes, {@code R || S}, cada metade com 32. Entregar o DER cru rende 403 do push service
     * sem nenhuma pista no corpo da resposta.
     */
    static byte[] toJoseSignature(byte[] der) throws GeneralSecurityException {
        if (der.length < 8 || der[0] != 0x30) {
            throw new GeneralSecurityException("Malformed ECDSA signature");
        }
        // Comprimento do SEQUENCE: forma curta (1 byte) ou longa (0x8N seguido de N bytes).
        int offset = 2;
        if ((der[1] & 0x80) != 0) {
            offset = 2 + (der[1] & 0x7F);
        }
        if (der[offset] != 0x02) {
            throw new GeneralSecurityException("Malformed ECDSA signature: missing R");
        }
        int lengthR = der[offset + 1] & 0xFF;
        BigInteger r = new BigInteger(Arrays.copyOfRange(der, offset + 2, offset + 2 + lengthR));

        int offsetS = offset + 2 + lengthR;
        if (der[offsetS] != 0x02) {
            throw new GeneralSecurityException("Malformed ECDSA signature: missing S");
        }
        int lengthS = der[offsetS + 1] & 0xFF;
        BigInteger s = new BigInteger(Arrays.copyOfRange(der, offsetS + 2, offsetS + 2 + lengthS));

        byte[] jose = new byte[WebPushKeys.FIELD_SIZE * 2];
        writeFixed(r, jose, 0);
        writeFixed(s, jose, WebPushKeys.FIELD_SIZE);
        return jose;
    }

    private static void writeFixed(BigInteger value, byte[] target, int offset) {
        byte[] bytes = value.toByteArray();
        int length = Math.min(bytes.length, WebPushKeys.FIELD_SIZE);
        int source = bytes.length - length;
        System.arraycopy(bytes, source, target, offset + WebPushKeys.FIELD_SIZE - length, length);
    }

}
