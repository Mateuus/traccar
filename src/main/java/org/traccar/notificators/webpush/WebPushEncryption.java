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

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.Arrays;

/**
 * Cifragem da mensagem de Web Push: RFC 8291 (derivacao das chaves) sobre RFC 8188 (formato
 * "aes128gcm" do corpo). Sem dependencia externa — tudo o que e preciso ja existe no JCE do JDK.
 *
 * Nao usar biblioteca aqui e decisao deliberada: as candidatas arrastam BouncyCastle e jose4j, e
 * este repositorio e um fork que precisa continuar fazendo merge do upstream sem brigar por
 * dependencia. A contrapartida e que a correcao tem de ser provada — {@code WebPushEncryptionTest}
 * confere cada etapa contra o vetor da secao 5 do RFC 8291.
 *
 * O corpo produzido tem a forma:
 * <pre>
 *   salt(16) || rs(4, big-endian) || idlen(1) || chave_publica_efemera(65) || ciphertext
 * </pre>
 */
public final class WebPushEncryption {

    private static final byte[] KEY_INFO_PREFIX = "WebPush: info".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] CEK_INFO = infoWithTerminator("Content-Encoding: aes128gcm");
    private static final byte[] NONCE_INFO = infoWithTerminator("Content-Encoding: nonce");

    private static final int SALT_SIZE = 16;
    private static final int CEK_SIZE = 16;
    private static final int NONCE_SIZE = 12;
    private static final int IKM_SIZE = 32;
    private static final int AUTH_TAG_BITS = 128;
    private static final int AUTH_TAG_SIZE = AUTH_TAG_BITS / 8;

    /**
     * Tamanho de registro anunciado no cabecalho. Mandamos sempre um registro unico, entao este
     * valor so precisa ser maior que o payload cifrado; 4096 e o que o exemplo do RFC usa e cabe
     * folgado no limite de 4 KB que os push services praticam.
     */
    private static final int RECORD_SIZE = 4096;

    /** Delimitador do RFC 8188 para o ultimo (aqui, unico) registro. */
    private static final byte LAST_RECORD_DELIMITER = 0x02;

    private static final SecureRandom RANDOM = new SecureRandom();

    private WebPushEncryption() {
    }

    private static byte[] infoWithTerminator(String value) {
        byte[] ascii = value.getBytes(StandardCharsets.US_ASCII);
        return Arrays.copyOf(ascii, ascii.length + 1);
    }

    /**
     * Cifra o payload para uma inscricao, sorteando salt e par efemero.
     *
     * @param plaintext  conteudo a entregar (JSON da notificacao)
     * @param uaPublic   chave publica da inscricao (p256dh), 65 bytes
     * @param authSecret segredo de autenticacao da inscricao (auth), 16 bytes
     */
    public static byte[] encrypt(byte[] plaintext, byte[] uaPublic, byte[] authSecret)
            throws GeneralSecurityException {
        byte[] salt = new byte[SALT_SIZE];
        RANDOM.nextBytes(salt);
        return encrypt(plaintext, uaPublic, authSecret, WebPushKeys.generateKeyPair(), salt);
    }

    /**
     * Variante com salt e par efemero injetados. Existe para o teste poder reproduzir o vetor do
     * RFC — em producao use a sobrecarga de tres argumentos, que sorteia ambos.
     */
    static byte[] encrypt(byte[] plaintext, byte[] uaPublic, byte[] authSecret, KeyPair keyPair, byte[] salt)
            throws GeneralSecurityException {

        int payloadSize = plaintext.length + 1 + AUTH_TAG_SIZE;
        if (payloadSize > RECORD_SIZE) {
            throw new GeneralSecurityException("Web Push payload exceeds a single record: " + payloadSize);
        }

        byte[] asPublic = WebPushKeys.encodePublicKey((ECPublicKey) keyPair.getPublic());
        byte[] secret = sharedSecret((ECPrivateKey) keyPair.getPrivate(), uaPublic);

        byte[] ikm = hkdf(authSecret, secret, keyInfo(uaPublic, asPublic), IKM_SIZE);
        byte[] prk = hkdfExtract(salt, ikm);
        byte[] cek = hkdfExpand(prk, CEK_INFO, CEK_SIZE);
        byte[] nonce = hkdfExpand(prk, NONCE_INFO, NONCE_SIZE);

        // RFC 8188: o registro carrega o texto claro seguido do delimitador, e so entao e cifrado.
        byte[] record = Arrays.copyOf(plaintext, plaintext.length + 1);
        record[plaintext.length] = LAST_RECORD_DELIMITER;

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(cek, "AES"), new GCMParameterSpec(AUTH_TAG_BITS, nonce));
        byte[] ciphertext = cipher.doFinal(record);

        ByteBuffer body = ByteBuffer.allocate(SALT_SIZE + 4 + 1 + asPublic.length + ciphertext.length);
        body.put(salt);
        body.putInt(RECORD_SIZE);
        body.put((byte) asPublic.length);
        body.put(asPublic);
        body.put(ciphertext);
        return body.array();
    }

    /** Segredo ECDH entre a nossa chave efemera e a chave publica da inscricao. */
    static byte[] sharedSecret(ECPrivateKey privateKey, byte[] uaPublic) throws GeneralSecurityException {
        KeyAgreement agreement = KeyAgreement.getInstance("ECDH");
        agreement.init(privateKey);
        agreement.doPhase(WebPushKeys.decodePublicKey(uaPublic), true);
        return agreement.generateSecret();
    }

    /** {@code "WebPush: info" || 0x00 || chave_do_cliente || chave_efemera} (RFC 8291, secao 3.4). */
    static byte[] keyInfo(byte[] uaPublic, byte[] asPublic) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.writeBytes(KEY_INFO_PREFIX);
        out.write(0);
        out.writeBytes(uaPublic);
        out.writeBytes(asPublic);
        return out.toByteArray();
    }

    static byte[] hkdf(byte[] salt, byte[] ikm, byte[] info, int length) throws GeneralSecurityException {
        return hkdfExpand(hkdfExtract(salt, ikm), info, length);
    }

    static byte[] hkdfExtract(byte[] salt, byte[] ikm) throws GeneralSecurityException {
        return hmacSha256(salt, ikm);
    }

    /**
     * HKDF-Expand limitado a um bloco (32 bytes). Todas as saidas daqui — IKM, CEK e nonce — cabem
     * num bloco de HMAC-SHA256, entao a iteracao completa do RFC 5869 seria codigo morto.
     */
    static byte[] hkdfExpand(byte[] prk, byte[] info, int length) throws GeneralSecurityException {
        if (length > IKM_SIZE) {
            throw new GeneralSecurityException("HKDF expansion beyond one block is not supported");
        }
        byte[] input = Arrays.copyOf(info, info.length + 1);
        input[info.length] = 1;
        return Arrays.copyOf(hmacSha256(prk, input), length);
    }

    private static byte[] hmacSha256(byte[] key, byte[] data) throws GeneralSecurityException {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key, "HmacSHA256"));
        return mac.doFinal(data);
    }

}
