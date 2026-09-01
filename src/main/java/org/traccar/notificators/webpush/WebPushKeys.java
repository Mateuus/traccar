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
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.util.Base64;

/**
 * Conversao de chaves P-256 entre o formato do Web Push e o do JCE.
 *
 * O Web Push trafega chaves publicas como ponto NAO comprimido do X9.62 (65 bytes: 0x04 || X || Y)
 * e chaves privadas como o escalar cru de 32 bytes, ambos em base64url sem padding. O JCE quer
 * ECPublicKey / ECPrivateKey. Todo o resto do modulo assume essa fronteira ja atravessada.
 */
public final class WebPushKeys {

    /** Curva do Web Push: P-256 (secp256r1). RFC 8291 nao permite outra. */
    private static final String CURVE = "secp256r1";

    /** Tamanho de X, de Y e do escalar privado em P-256. */
    public static final int FIELD_SIZE = 32;

    /** Ponto nao comprimido: prefixo 0x04 + X + Y. */
    public static final int PUBLIC_KEY_SIZE = 1 + FIELD_SIZE * 2;

    private static final byte UNCOMPRESSED_PREFIX = 0x04;

    private WebPushKeys() {
    }

    public static ECParameterSpec parameters() throws GeneralSecurityException {
        AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
        parameters.init(new ECGenParameterSpec(CURVE));
        return parameters.getParameterSpec(ECParameterSpec.class);
    }

    public static KeyPair generateKeyPair() throws GeneralSecurityException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec(CURVE));
        return generator.generateKeyPair();
    }

    public static ECPublicKey decodePublicKey(byte[] encoded) throws GeneralSecurityException {
        if (encoded.length != PUBLIC_KEY_SIZE || encoded[0] != UNCOMPRESSED_PREFIX) {
            throw new GeneralSecurityException("Web Push public key must be an uncompressed P-256 point");
        }
        BigInteger x = new BigInteger(1, encoded, 1, FIELD_SIZE);
        BigInteger y = new BigInteger(1, encoded, 1 + FIELD_SIZE, FIELD_SIZE);
        ECPublicKeySpec spec = new ECPublicKeySpec(new ECPoint(x, y), parameters());
        return (ECPublicKey) KeyFactory.getInstance("EC").generatePublic(spec);
    }

    public static ECPrivateKey decodePrivateKey(byte[] encoded) throws GeneralSecurityException {
        ECPrivateKeySpec spec = new ECPrivateKeySpec(new BigInteger(1, encoded), parameters());
        return (ECPrivateKey) KeyFactory.getInstance("EC").generatePrivate(spec);
    }

    public static byte[] encodePublicKey(ECPublicKey key) {
        byte[] encoded = new byte[PUBLIC_KEY_SIZE];
        encoded[0] = UNCOMPRESSED_PREFIX;
        writeFixed(key.getW().getAffineX(), encoded, 1);
        writeFixed(key.getW().getAffineY(), encoded, 1 + FIELD_SIZE);
        return encoded;
    }

    /**
     * Escreve o inteiro em exatamente {@link #FIELD_SIZE} bytes.
     *
     * O {@code toByteArray()} do BigInteger nao serve direto: ele acrescenta um 0x00 a esquerda
     * quando o bit mais significativo esta ligado (33 bytes) e encurta quando o valor tem zeros a
     * esquerda (menos de 32). Nos dois casos o ponto sairia deslocado e a chave, invalida.
     */
    private static void writeFixed(BigInteger value, byte[] target, int offset) {
        byte[] bytes = value.toByteArray();
        int length = Math.min(bytes.length, FIELD_SIZE);
        int source = bytes.length - length;
        System.arraycopy(bytes, source, target, offset + FIELD_SIZE - length, length);
    }

    public static byte[] decodeBase64(String value) {
        return Base64.getUrlDecoder().decode(value);
    }

    public static String encodeBase64(byte[] value) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(value);
    }

}
