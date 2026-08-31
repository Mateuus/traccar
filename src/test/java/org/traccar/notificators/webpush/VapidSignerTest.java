package org.traccar.notificators.webpush;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.Signature;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.time.Instant;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class VapidSignerTest {

    private static final String ENDPOINT = "https://web.push.apple.com/QBcRSTUv/wxyz-1234";
    private static final String SUBJECT = "mailto:contato@rdmrastreamento.com.br";

    /**
     * Refaz o caminho inverso do {@code toJoseSignature}: R || S de volta para DER, para poder pedir
     * ao proprio JCE que valide a assinatura. Se a conversao perder ou deslocar um byte, a
     * verificacao falha — que e exatamente o 403 silencioso que o push service devolveria.
     */
    private static byte[] toDerSignature(byte[] jose) {
        BigInteger r = new BigInteger(1, Arrays.copyOfRange(jose, 0, 32));
        BigInteger s = new BigInteger(1, Arrays.copyOfRange(jose, 32, 64));
        byte[] rb = r.toByteArray();
        byte[] sb = s.toByteArray();
        ByteArrayOutputStream content = new ByteArrayOutputStream();
        content.write(0x02);
        content.write(rb.length);
        content.writeBytes(rb);
        content.write(0x02);
        content.write(sb.length);
        content.writeBytes(sb);
        byte[] body = content.toByteArray();
        ByteArrayOutputStream der = new ByteArrayOutputStream();
        der.write(0x30);
        der.write(body.length);
        der.writeBytes(body);
        return der.toByteArray();
    }

    @Test
    public void testAuthorizationHeaderIsVerifiable() throws Exception {
        KeyPair keyPair = WebPushKeys.generateKeyPair();
        byte[] publicKey = WebPushKeys.encodePublicKey((ECPublicKey) keyPair.getPublic());

        String header = VapidSigner.authorization(ENDPOINT, SUBJECT, (ECPrivateKey) keyPair.getPrivate(), publicKey);

        assertTrue(header.startsWith("vapid t="), header);
        String token = header.substring("vapid t=".length(), header.indexOf(", k="));
        String key = header.substring(header.indexOf(", k=") + 4);
        assertEquals(WebPushKeys.encodeBase64(publicKey), key);

        String[] parts = token.split("\\.");
        assertEquals(3, parts.length);

        ObjectMapper mapper = new ObjectMapper();
        JsonNode head = mapper.readTree(WebPushKeys.decodeBase64(parts[0]));
        assertEquals("JWT", head.get("typ").asText());
        assertEquals("ES256", head.get("alg").asText());

        JsonNode claims = mapper.readTree(WebPushKeys.decodeBase64(parts[1]));
        // O "aud" e o ORIGIN do endpoint: sem o caminho. Mandar a URL inteira e recusado.
        assertEquals("https://web.push.apple.com", claims.get("aud").asText());
        assertEquals(SUBJECT, claims.get("sub").asText());
        long expiration = claims.get("exp").asLong();
        long now = Instant.now().getEpochSecond();
        assertTrue(expiration > now, "token ja expirado");
        assertTrue(expiration <= now + 24 * 60 * 60, "RFC 8292 limita a validade a 24 h");

        byte[] jose = WebPushKeys.decodeBase64(parts[2]);
        assertEquals(64, jose.length, "JWS exige R || S com 64 bytes");

        Signature verifier = Signature.getInstance("SHA256withECDSA");
        verifier.initVerify(keyPair.getPublic());
        verifier.update((parts[0] + "." + parts[1]).getBytes(StandardCharsets.US_ASCII));
        assertTrue(verifier.verify(toDerSignature(jose)), "assinatura nao confere com a chave publica");
    }

    /**
     * Um R ou S com zeros a esquerda encurta a codificacao DER. Repetir a assinatura muitas vezes
     * faz esse caso aparecer; todas tem de sair com 64 bytes e continuar validas.
     */
    @Test
    public void testShortIntegersStillProduceSixtyFourBytes() throws Exception {
        KeyPair keyPair = WebPushKeys.generateKeyPair();
        byte[] publicKey = WebPushKeys.encodePublicKey((ECPublicKey) keyPair.getPublic());
        for (int i = 0; i < 200; i++) {
            String header = VapidSigner.authorization(
                    ENDPOINT, SUBJECT, (ECPrivateKey) keyPair.getPrivate(), publicKey);
            String token = header.substring("vapid t=".length(), header.indexOf(", k="));
            String[] parts = token.split("\\.");
            byte[] jose = WebPushKeys.decodeBase64(parts[2]);
            assertEquals(64, jose.length);
            Signature verifier = Signature.getInstance("SHA256withECDSA");
            verifier.initVerify(keyPair.getPublic());
            verifier.update((parts[0] + "." + parts[1]).getBytes(StandardCharsets.US_ASCII));
            assertTrue(verifier.verify(toDerSignature(jose)));
        }
    }

}
