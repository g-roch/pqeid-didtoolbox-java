package ch.admin.bj.swiyu.didtoolbox.webvh;

import ch.admin.bj.swiyu.didtoolbox.AbstractUtilTestBase;
import ch.admin.bj.swiyu.didtoolbox.context.DidLogCreatorContext;
import ch.admin.bj.swiyu.didtoolbox.model.DidMethodEnum;
import ch.admin.bj.swiyu.didtoolbox.vc_data_integrity.EdDsaJcs2022VcDataIntegrityCryptographicSuite;
import ch.admin.bj.swiyu.didtoolbox.vc_data_integrity.MlDsa65Ed25519JcsPqeidVcDataIntegrityCryptographicSuite;
import ch.admin.eid.didresolver.Did;
import com.google.gson.JsonParser;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.net.URL;

import static org.junit.jupiter.api.Assertions.*;

/**
 * PQEID: creating a hybrid did:webvh:1.0-pqeid log with didtoolbox, and resolving it with the (Rust) resolver.
 */
@SuppressWarnings("PMD")
class WebVerifiableHistoryCreatorPqeidTest extends AbstractUtilTestBase {

    private static URL registryUrl() throws Exception {
        return URI.create("https://identifier-reg.example.com/api/v1/did/18fa7c77-9dd1-4e20-a147-fb1bec146085").toURL();
    }

    @Test
    void hybridSuiteCreatesAPqeidLogThatResolves() throws Exception {
        var suite = new MlDsa65Ed25519JcsPqeidVcDataIntegrityCryptographicSuite();
        var didLog = WebVerifiableHistoryCreator.builder(suite)
                .authentications(TEST_AUTHENTICATIONS)
                .assertionMethods(TEST_ASSERTION_METHODS)
                .build()
                .createDidLog(registryUrl());

        var entry = JsonParser.parseString(didLog).getAsJsonObject();
        var params = entry.getAsJsonObject("parameters");
        assertEquals("did:webvh:1.0-pqeid", params.get("method").getAsString());
        assertEquals(suite.getVerificationKeyMultibase(), params.getAsJsonArray("updateKeys").get(0).getAsString());
        assertEquals("mldsa65-ed25519-jcs-pqeid",
                entry.getAsJsonArray("proof").get(0).getAsJsonObject().get("cryptosuite").getAsString());

        // the Rust resolver (D3) accepts it: SCID, entry hash, hybrid proof, method version
        var did = entry.getAsJsonObject("state").get("id").getAsString();
        assertDoesNotThrow(() -> new Did(did).resolveAll(didLog));
    }

    @Test
    void eddsaSuiteStillCreatesAStandardLog() throws Exception {
        var didLog = WebVerifiableHistoryCreator.builder(new EdDsaJcs2022VcDataIntegrityCryptographicSuite())
                .authentications(TEST_AUTHENTICATIONS)
                .assertionMethods(TEST_ASSERTION_METHODS)
                .build()
                .createDidLog(registryUrl());
        var params = JsonParser.parseString(didLog).getAsJsonObject().getAsJsonObject("parameters");
        assertEquals("did:webvh:1.0", params.get("method").getAsString());
    }

    @Test
    void requestedVersionAndSuiteMustAgree() {
        // did:webvh:1.0 with the hybrid suite, and did:webvh:1.0-pqeid with the Ed25519 suite: both refused
        assertThrows(IllegalArgumentException.class, () -> DidLogCreatorContext
                .builder(DidMethodEnum.WEBVH_1_0, new MlDsa65Ed25519JcsPqeidVcDataIntegrityCryptographicSuite())
                .authentications(TEST_AUTHENTICATIONS)
                .assertionMethods(TEST_ASSERTION_METHODS)
                .build()
                .create(registryUrl()));
        assertThrows(IllegalArgumentException.class, () -> DidLogCreatorContext
                .builder(DidMethodEnum.WEBVH_1_0_PQEID, new EdDsaJcs2022VcDataIntegrityCryptographicSuite())
                .authentications(TEST_AUTHENTICATIONS)
                .assertionMethods(TEST_ASSERTION_METHODS)
                .build()
                .create(registryUrl()));
    }

    @Test
    void contextWithPqeidVersionAndHybridSuiteCreatesAPqeidLog() throws Exception {
        var didLog = DidLogCreatorContext
                .builder(DidMethodEnum.WEBVH_1_0_PQEID, new MlDsa65Ed25519JcsPqeidVcDataIntegrityCryptographicSuite())
                .authentications(TEST_AUTHENTICATIONS)
                .assertionMethods(TEST_ASSERTION_METHODS)
                .build()
                .create(registryUrl());
        assertEquals("did:webvh:1.0-pqeid", JsonParser.parseString(didLog).getAsJsonObject()
                .getAsJsonObject("parameters").get("method").getAsString());
        assertEquals(DidMethodEnum.WEBVH_1_0_PQEID, DidMethodEnum.detectDidMethod(didLog));
    }

    @Test
    void methodVersionParses() throws Exception {
        assertEquals(DidMethodEnum.WEBVH_1_0_PQEID, DidMethodEnum.parse("did:webvh:1.0-pqeid"));
        assertTrue(DidMethodEnum.WEBVH_1_0_PQEID.isWebVh10());
        assertTrue(DidMethodEnum.WEBVH_1_0_PQEID.isPqeid());
        assertFalse(DidMethodEnum.WEBVH_1_0.isPqeid());
    }
}
