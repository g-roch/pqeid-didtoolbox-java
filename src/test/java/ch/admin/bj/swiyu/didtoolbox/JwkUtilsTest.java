package ch.admin.bj.swiyu.didtoolbox;

import com.google.gson.JsonParser;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.MLDSASigner;
import com.nimbusds.jose.crypto.MLDSAVerifier;
import com.nimbusds.jose.jwk.MLDSAKey;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.Arrays;
import java.util.HashSet;

import static org.junit.jupiter.api.Assertions.*;

// This will suppress all PMD warnings in this class
@SuppressWarnings({"PMD"})
class JwkUtilsTest {

    private static void assertGeneratePublicEC256(String json, String kid) {
        assertNotNull(json);
        var publicJwkJsonObject = JsonParser.parseString(json).getAsJsonObject();
        assertTrue(publicJwkJsonObject.has("kty"));
        assertEquals("EC", publicJwkJsonObject.get("kty").getAsString());
        assertTrue(publicJwkJsonObject.has("crv"));
        assertEquals("P-256", publicJwkJsonObject.get("crv").getAsString());
        if (kid != null) {
            assertTrue(publicJwkJsonObject.has("kid"));
            assertEquals(kid, publicJwkJsonObject.get("kid").getAsString());
        }

        assertFalse(publicJwkJsonObject.has("d")); // what makes it public and not private
    }

    /**
     * Helper for the PEM export.
     *
     * @param privatePemFile to read the private key from
     * @param publicPemFile  to read the public key from
     * @throws IOException   if an I/O error occurs reading from the file or a malformed or unmappable byte sequence is read
     * @throws JOSEException If EC JWK key parsing failed or if the JWS object couldn't be signed/verified
     */
    private static void ecPemSanityCheck(File privatePemFile, File publicPemFile)
            throws IOException, JOSEException {

        final ECPrivateKey privKey = (ECPrivateKey) PemUtils.parsePemKeyPairFile(privatePemFile).getPrivate();
        final ECPublicKey publicKey = (ECPublicKey) PemUtils.parsePemPublicKey(Files.newBufferedReader(publicPemFile.toPath()));

        JWSObject jwsObject = new JWSObject(
                new JWSHeader.Builder(JWSAlgorithm.ES256).build(),
                new Payload("hello world"));
        jwsObject.sign(new ECDSASigner(privKey));

        //String s = jwsObject.serialize(); // compact form

        if (!jwsObject.verify(new ECDSAVerifier(publicKey)) || (!"hello world".equals(jwsObject.getPayload().toString()))) {
            throw new IllegalArgumentException("exported key do not match");
        }
    }

    @Test
    void testGeneratePublicEC256() {
        assertDoesNotThrow(() -> {
            // No PEM files are exported here
            assertGeneratePublicEC256(JwkUtils.generatePublicEC256("auth-key-01", null, false), null); // MUT
        });
    }

    @Test
    void testGeneratePublicEC256WithOutputOverwriteExisting() {
        assertDoesNotThrow(() -> {
            var tempFile = File.createTempFile("mypublic", "");
            // Exists at the moment of key generation, and should therefore be overwritten if forceOverwritten == true
            tempFile.deleteOnExit();

            var kid = "auth-key-01";
            assertGeneratePublicEC256(JwkUtils.generatePublicEC256(kid, tempFile, true), kid); // MUT

            // Verification of the exported PEM files
            assertNotEquals(0, Files.size(tempFile.toPath()));

            var pubTempFile = new File(tempFile.getPath() + ".pub");
            pubTempFile.deleteOnExit();

            assertNotEquals(0, Files.size(pubTempFile.toPath()));
            ecPemSanityCheck(tempFile, pubTempFile);
        });
    }

    @Test
    void testGeneratePublicEC256WithOutputNoOverwriteExistingThrowsException() {
        File tempFile = null;
        try {
            tempFile = File.createTempFile("mypublic", "");
            // Exists at the moment of key generation, and should NOT be overwritten if forceOverwritten == false
            tempFile.deleteOnExit();
        } catch (Exception e) {
            fail(e);
        }

        File finalTempFile = tempFile;
        var exc = assertThrowsExactly(IOException.class, () -> {
            // kid is irrelevant here
            JwkUtils.generatePublicEC256(null, finalTempFile, false); // MUT
        });
        assertTrue(exc.getMessage().contains("The PEM file(s) exist(s) already and will remain intact until overwrite mode is engaged"));

        try {
            // The temp file should remain empty
            assertEquals(0, Files.size(tempFile.toPath()));
            // And NO matching .pub file should be created
            var pubTempFile = new File(tempFile.getPath() + ".pub");
            pubTempFile.deleteOnExit();
            assertFalse((pubTempFile.exists()));
        } catch (Exception e) {
            fail(e);
        }
    }

    @Test
    void testGeneratePublicEC256WithOutputOverwriteNonExisting() {
        assertDoesNotThrow(() -> {
            var tempFile = File.createTempFile("mypublic", "");
            // Delete it immediately, so it will NOT exist at the moment of key generation and should therefore be created regardless of forceOverwritten flag
            tempFile.deleteOnExit();

            var kid = "auth-key-01";
            assertGeneratePublicEC256(JwkUtils.generatePublicEC256(kid, tempFile, true), kid); // MUT

            // Verification of the exported PEM files
            assertNotEquals(0, Files.size(tempFile.toPath()));
            var pubTempFile = new File(tempFile.getPath() + ".pub");
            pubTempFile.deleteOnExit(); // clean it up
            assertNotEquals(0, Files.size(pubTempFile.toPath()));
            ecPemSanityCheck(tempFile, pubTempFile);
        });
    }

    @Test
    void testLoadECPublicJWKasJSON() {
        assertDoesNotThrow(() -> {
            var jwk = JwkUtils.loadECPublicJWKasJSON(Path.of("src/test/data/auth-key-01.pub"), "my-auth-key-01"); // MUT
            assertNotNull(jwk);
            jwk = JwkUtils.loadECPublicJWKasJSON(Path.of("src/test/data/assert-key-01.pub"), "my-assert-key-01"); // MUT
            assertNotNull(jwk);
        });
    }

    @Test
    void testLoadECPublicJWKasJSONThrowsIllegalArgumentException() {

        /* A "kid" featuring URIs "Reserved Characters" (incl. "Percent-Encoding") must fail:
        pct-encoded = "%" HEXDIG HEXDIG
        reserved    = gen-delims / sub-delims
        gen-delims  = ":" / "/" / "?" / "#" / "[" / "]" / "@"
        sub-delims  = "!" / "$" / "&" / "'" / "(" / ")" / "*" / "+" / "," / ";" / "="
         */
        var kids = new HashSet<>(Arrays.asList(
                "",
                "kid-contains-%-gen-delim",
                "kid-contains-:-gen-delim",
                "kid-contains-/-gen-delim",
                "kid-contains-?-gen-delim",
                "kid-contains-#-gen-delim",
                "kid-contains-[-gen-delim",
                "kid-contains-]-gen-delim",
                "kid-contains-@-gen-delim",
                "kid-contains-!-sub-delim",
                "kid-contains-$-sub-delim",
                "kid-contains-&-sub-delim",
                "kid-contains-'-sub-delim",
                "kid-contains-\"-sub-delim",
                "kid-contains-(-sub-delim",
                "kid-contains-)-sub-delim",
                "kid-contains-*-sub-delim",
                "kid-contains-+-sub-delim",
                "kid-contains-,-sub-delim",
                "kid-contains-;-sub-delim",
                "kid-contains-=-sub-delim"
        ));

        for (var kid : kids) {
            var ex = assertThrowsExactly(IllegalArgumentException.class, () -> {
                JwkUtils.loadECPublicJWKasJSON(Path.of("src/test/data/auth-key-01.pub"), kid); // MUT
            });
            assertTrue(ex.getMessage().contains("must be a regular case-sensitive string featuring no URIs reserved characters"));
        }
    }

    // PQEID: ML-DSA support below.

    private static void assertGeneratePublicMLDSA44(String json, String kid) {
        assertNotNull(json);
        var publicJwkJsonObject = JsonParser.parseString(json).getAsJsonObject();
        assertTrue(publicJwkJsonObject.has("kty"));
        assertEquals("AKP", publicJwkJsonObject.get("kty").getAsString());
        assertTrue(publicJwkJsonObject.has("alg"));
        assertEquals("ML-DSA-44", publicJwkJsonObject.get("alg").getAsString());
        assertTrue(publicJwkJsonObject.has("pub"));
        if (kid != null) {
            assertTrue(publicJwkJsonObject.has("kid"));
            assertEquals(kid, publicJwkJsonObject.get("kid").getAsString());
        }

        assertFalse(publicJwkJsonObject.has("priv")); // what makes it public and not private
    }

    /**
     * Helper for the PEM export: sign/verify round-trip proving the exported PEM files
     * actually feature a matching, functional ML-DSA key pair (mirrors {@link #ecPemSanityCheck(File, File)}).
     */
    private static void mldsaPemSanityCheck(File privatePemFile, File publicPemFile)
            throws IOException, JOSEException {

        var privateKey = PemUtils.parsePemPrivateKey(Files.newBufferedReader(privatePemFile.toPath()));
        var publicKey = PemUtils.parsePemPublicKey(Files.newBufferedReader(publicPemFile.toPath()));

        var mldsaPrivateJwk = new MLDSAKey.Builder(privateKey, publicKey).build();
        var mldsaPublicJwk = new MLDSAKey.Builder(publicKey).build();

        JWSObject jwsObject = new JWSObject(
                new JWSHeader.Builder(JWSAlgorithm.ML_DSA_44).build(),
                new Payload("hello world"));
        jwsObject.sign(new MLDSASigner(mldsaPrivateJwk));

        if (!jwsObject.verify(new MLDSAVerifier(mldsaPublicJwk)) || (!"hello world".equals(jwsObject.getPayload().toString()))) {
            throw new IllegalArgumentException("exported key do not match");
        }
    }

    @Test
    void testGeneratePublicMLDSA44() {
        assertDoesNotThrow(() -> {
            // No PEM files are exported here
            assertGeneratePublicMLDSA44(JwkUtils.generatePublicMLDSA44("auth-key-01", null, false), "auth-key-01"); // MUT
        });
    }

    @Test
    void testGeneratePublicMLDSA44WithOutputOverwriteExisting() {
        assertDoesNotThrow(() -> {
            var tempFile = File.createTempFile("mypublic-mldsa", "");
            tempFile.deleteOnExit();

            var kid = "auth-key-01";
            assertGeneratePublicMLDSA44(JwkUtils.generatePublicMLDSA44(kid, tempFile, true), kid); // MUT

            assertNotEquals(0, Files.size(tempFile.toPath()));

            var pubTempFile = new File(tempFile.getPath() + ".pub");
            pubTempFile.deleteOnExit();

            assertNotEquals(0, Files.size(pubTempFile.toPath()));
            mldsaPemSanityCheck(tempFile, pubTempFile);
        });
    }

    @Test
    void testLoadPublicJWKasJSON() {
        assertDoesNotThrow(() -> {
            // Dispatches to the EC branch, same fixtures/behaviour as loadECPublicJWKasJSON
            var jwk = JwkUtils.loadPublicJWKasJSON(Path.of("src/test/data/auth-key-01.pub"), "my-auth-key-01"); // MUT
            assertNotNull(jwk);
            assertEquals("EC", JsonParser.parseString(jwk).getAsJsonObject().get("kty").getAsString());

            // Dispatches to the ML-DSA branch
            jwk = JwkUtils.loadPublicJWKasJSON(Path.of("src/test/data/mldsa-key-01.pub"), "my-mldsa-key-01"); // MUT
            assertNotNull(jwk);
            var jwkJsonObject = JsonParser.parseString(jwk).getAsJsonObject();
            assertEquals("AKP", jwkJsonObject.get("kty").getAsString());
            assertEquals("ML-DSA-44", jwkJsonObject.get("alg").getAsString());
            assertEquals("my-mldsa-key-01", jwkJsonObject.get("kid").getAsString());
        });
    }
}
