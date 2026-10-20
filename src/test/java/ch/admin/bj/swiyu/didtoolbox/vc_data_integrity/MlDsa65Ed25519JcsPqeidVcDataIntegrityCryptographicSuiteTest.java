package ch.admin.bj.swiyu.didtoolbox.vc_data_integrity;

import ch.admin.eid.did_sidekicks.CompositeVerifyingKey;
import ch.admin.eid.did_sidekicks.DataIntegrityProof;
import ch.admin.eid.did_sidekicks.DidSidekicksException;
import ch.admin.eid.did_sidekicks.JcsSha256Hasher;
import ch.admin.eid.did_sidekicks.MlDsa65Ed25519JcsPqeidCryptosuite;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.junit.jupiter.api.Test;

import java.time.ZonedDateTime;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * PQEID: the Java adapter of the hybrid {@code mldsa65-ed25519-jcs-pqeid} suite. The cryptography itself is tested in
 * Rust (did_sidekicks, incl. the draft-05 composite vector); here: key handling and that a Java-made proof verifies
 * with the Rust verifier, and fails when the document changes.
 */
@SuppressWarnings("PMD")
class MlDsa65Ed25519JcsPqeidVcDataIntegrityCryptographicSuiteTest {

    private static final String DOC = "{\"@context\":[\"https://www.w3.org/ns/did/v1\"],\"id\":\"did:example:123\"}";

    @Test
    void secretKeyMultibaseRoundtrip() throws Exception {
        var suite = new MlDsa65Ed25519JcsPqeidVcDataIntegrityCryptographicSuite();
        var again = new MlDsa65Ed25519JcsPqeidVcDataIntegrityCryptographicSuite(suite.getSecretKeyMultibase());
        assertEquals(suite.getVerificationKeyMultibase(), again.getVerificationKeyMultibase());
        assertTrue(suite.isKeyMultibaseInSet(Set.of(suite.getVerificationKeyMultibase())));
        assertFalse(suite.isKeyMultibaseInSet(Set.of(new MlDsa65Ed25519JcsPqeidVcDataIntegrityCryptographicSuite().getVerificationKeyMultibase())));
    }

    @Test
    void notACompositeSecretKeyIsRefused() {
        // an Ed25519 secret key multibase (W3C vc-di-eddsa example), and the composite *public* multikey
        assertThrows(VcDataIntegrityCryptographicSuiteException.class,
                () -> new MlDsa65Ed25519JcsPqeidVcDataIntegrityCryptographicSuite("z3u2en7t5LR2WtQH5PfFqMqwVHBeXouLzo6haApm8XHqvjxq"));
        var publicMultikey = new MlDsa65Ed25519JcsPqeidVcDataIntegrityCryptographicSuite().getVerificationKeyMultibase();
        assertThrows(VcDataIntegrityCryptographicSuiteException.class,
                () -> new MlDsa65Ed25519JcsPqeidVcDataIntegrityCryptographicSuite(publicMultikey));
    }

    @Test
    void javaProofVerifiesWithTheRustVerifierAndDetectsTampering() throws Exception {
        var suite = new MlDsa65Ed25519JcsPqeidVcDataIntegrityCryptographicSuite();
        var secured = JsonParser.parseString(suite.addProof(DOC, null, "assertionMethod", ZonedDateTime.now()))
                .getAsJsonObject();

        var proof = secured.getAsJsonArray("proof").get(0).getAsJsonObject();
        var multikey = suite.getVerificationKeyMultibase();
        assertEquals(MlDsa65Ed25519JcsPqeidVcDataIntegrityCryptographicSuite.MLDSA65_ED25519_JCS_PQEID,
                proof.get("cryptosuite").getAsString());
        assertEquals("did:key:" + multikey + "#" + multikey, proof.get("verificationMethod").getAsString());

        var verifier = MlDsa65Ed25519JcsPqeidCryptosuite.Companion.fromVerifyingKey(
                CompositeVerifyingKey.Companion.fromMultibase(multikey));
        var parsedProof = DataIntegrityProof.Companion.fromJsonString(secured.getAsJsonArray("proof").toString());
        var hasher = JcsSha256Hasher.Companion.build();

        assertDoesNotThrow(() -> verifier.verifyProof(parsedProof, hasher.encodeHex(DOC)));

        var tampered = JsonParser.parseString(DOC).getAsJsonObject();
        tampered.addProperty("id", "did:example:attacker");
        assertThrows(DidSidekicksException.class, () -> verifier.verifyProof(parsedProof, hasher.encodeHex(tampered.toString())));
    }

    @Test
    void rawSignaturesAreNotOffered() {
        var suite = new MlDsa65Ed25519JcsPqeidVcDataIntegrityCryptographicSuite();
        assertThrows(UnsupportedOperationException.class, () -> suite.generateSignature(new byte[]{1, 2, 3}));
    }

    @Test
    void proofContextIsTakenFromTheDocument() throws Exception {
        var suite = new MlDsa65Ed25519JcsPqeidVcDataIntegrityCryptographicSuite();
        JsonObject proof = JsonParser.parseString(suite.addProof(DOC, null, "assertionMethod", ZonedDateTime.now()))
                .getAsJsonObject().getAsJsonArray("proof").get(0).getAsJsonObject();
        assertEquals("https://www.w3.org/ns/did/v1", proof.getAsJsonArray("@context").get(0).getAsString());
    }
}
