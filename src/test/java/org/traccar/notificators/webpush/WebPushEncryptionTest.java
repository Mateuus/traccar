package org.traccar.notificators.webpush;

import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.interfaces.ECPublicKey;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Vetor de teste da secao 5 do RFC 8291 ("Push Message Encryption Example").
 *
 * A cifragem do Web Push e escrita a mao (ver a justificativa em WebPushEncryption), entao a
 * unica prova aceitavel de que esta certa e reproduzir byte a byte o exemplo da especificacao.
 * Cada etapa intermediaria e conferida em separado de proposito: se um dia isto quebrar, a
 * asserção que falhar aponta o passo exato — ECDH, HKDF, CEK, nonce ou montagem do corpo.
 */
public class WebPushEncryptionTest {

    private static final String PLAINTEXT = "V2hlbiBJIGdyb3cgdXAsIEkgd2FudCB0byBiZSBhIHdhdGVybWVsb24";
    private static final String UA_PUBLIC =
            "BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4";
    private static final String AS_PUBLIC =
            "BP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8";
    private static final String AS_PRIVATE = "yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw";
    private static final String AUTH_SECRET = "BTBZMqHH6r4Tts7J_aSIgg";
    private static final String SALT = "DGv6ra1nlYgDCS1FRnbzlw";

    private static final String ECDH_SECRET = "kyrL1jIIOHEzg3sM2ZWRHDRB62YACZhhSlknJ672kSs";
    private static final String IKM = "S4lYMb_L0FxCeq0WhDx813KgSYqU26kOyzWUdsXYyrg";
    private static final String PRK = "09_eUZGrsvxChDCGRCdkLiDXrReGOEVeSCdCcPBSJSc";
    private static final String CEK = "oIhVW04MRdy2XN9CiKLxTg";
    private static final String NONCE = "4h_95klXJ5E_qnoN";

    private static final String BODY =
            "DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6Tlz"
            + "AC8wEqKK6PBru3jl7A_yl95bQpu6cVPTpK4Mqgkf1CXztLVBSt2Ks3oZwbuwXPXLWyouBWLVWGNWQexSgSxsj_Qulcy4a-fN";

    private static byte[] decode(String value) {
        return WebPushKeys.decodeBase64(value);
    }

    private static KeyPair applicationServerKeyPair() throws Exception {
        return new KeyPair(WebPushKeys.decodePublicKey(decode(AS_PUBLIC)), WebPushKeys.decodePrivateKey(decode(AS_PRIVATE)));
    }

    @Test
    public void testPublicKeyRoundTrip() throws Exception {
        ECPublicKey key = WebPushKeys.decodePublicKey(decode(UA_PUBLIC));
        assertEquals(UA_PUBLIC, WebPushKeys.encodeBase64(WebPushKeys.encodePublicKey(key)));
    }

    @Test
    public void testSharedSecret() throws Exception {
        byte[] secret = WebPushEncryption.sharedSecret(
                (java.security.interfaces.ECPrivateKey) applicationServerKeyPair().getPrivate(), decode(UA_PUBLIC));
        assertEquals(ECDH_SECRET, WebPushKeys.encodeBase64(secret));
    }

    @Test
    public void testKeyDerivation() throws Exception {
        byte[] keyInfo = WebPushEncryption.keyInfo(decode(UA_PUBLIC), decode(AS_PUBLIC));
        byte[] ikm = WebPushEncryption.hkdf(decode(AUTH_SECRET), decode(ECDH_SECRET), keyInfo, 32);
        assertEquals(IKM, WebPushKeys.encodeBase64(ikm));

        byte[] prk = WebPushEncryption.hkdfExtract(decode(SALT), ikm);
        assertEquals(PRK, WebPushKeys.encodeBase64(prk));

        byte[] cek = WebPushEncryption.hkdfExpand(prk, "Content-Encoding: aes128gcm\0".getBytes("US-ASCII"), 16);
        assertEquals(CEK, WebPushKeys.encodeBase64(cek));

        byte[] nonce = WebPushEncryption.hkdfExpand(prk, "Content-Encoding: nonce\0".getBytes("US-ASCII"), 12);
        assertEquals(NONCE, WebPushKeys.encodeBase64(nonce));
    }

    @Test
    public void testEncryptedBodyMatchesSpecification() throws Exception {
        byte[] body = WebPushEncryption.encrypt(
                decode(PLAINTEXT), decode(UA_PUBLIC), decode(AUTH_SECRET), applicationServerKeyPair(), decode(SALT));
        assertArrayEquals(decode(BODY), body);
    }

    @Test
    public void testRandomisedEncryptionProducesDistinctBodies() throws Exception {
        byte[] first = WebPushEncryption.encrypt(decode(PLAINTEXT), decode(UA_PUBLIC), decode(AUTH_SECRET));
        byte[] second = WebPushEncryption.encrypt(decode(PLAINTEXT), decode(UA_PUBLIC), decode(AUTH_SECRET));
        assertEquals(first.length, second.length);
        // Salt e chave efemera sao sorteados a cada envio: dois corpos iguais denunciariam reuso de nonce.
        assertArrayEquals(new boolean[]{false}, new boolean[]{java.util.Arrays.equals(first, second)});
    }

}
