package ch.admin.bj.swiyu.didtoolbox.vc_data_integrity;

import ch.admin.eid.did_sidekicks.CompositeSigningKey;
import ch.admin.eid.did_sidekicks.CryptoSuiteProofOptions;
import ch.admin.eid.did_sidekicks.DidSidekicksException;
import ch.admin.eid.did_sidekicks.MlDsa65Ed25519JcsPqeidCryptosuite;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonSyntaxException;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * PQEID: the hybrid {@code mldsa65-ed25519-jcs-pqeid} {@link VcDataIntegrityCryptographicSuite}
 * (composite ML-DSA-65-Ed25519 update keys, see docs/pqeid-hybrid-did-log-suite.md in the pqeid repo).
 * <p>
 * Like {@link EdDsaJcs2022VcDataIntegrityCryptographicSuite}, the cryptography itself is the Rust implementation
 * (did_sidekicks, through the Kotlin/JNA bindings); this class only adapts it to the didtoolbox interfaces.
 * <p>
 * Using this suite makes {@code WebVerifiableHistoryCreator} produce a {@code did:webvh:1.0-pqeid} log.
 */
public class MlDsa65Ed25519JcsPqeidVcDataIntegrityCryptographicSuite implements VcDataIntegrityCryptographicSuite {

    /**
     * The suite's name, as written in {@code proof.cryptosuite}.
     */
    public static final String MLDSA65_ED25519_JCS_PQEID = "mldsa65-ed25519-jcs-pqeid";

    private final CompositeSigningKey signingKey;
    private final MlDsa65Ed25519JcsPqeidCryptosuite cryptoSuite;

    /**
     * A fresh composite update key (OS randomness).
     */
    public MlDsa65Ed25519JcsPqeidVcDataIntegrityCryptographicSuite() {
        this(CompositeSigningKey.Companion.generate());
    }

    /**
     * @param secretKeyMultibase the composite secret key (private-use multicodec 0x300002), as written by
     *                           {@link #getSecretKeyMultibase()}
     * @throws VcDataIntegrityCryptographicSuiteException if it isn't a composite secret key
     */
    public MlDsa65Ed25519JcsPqeidVcDataIntegrityCryptographicSuite(String secretKeyMultibase) throws VcDataIntegrityCryptographicSuiteException {
        this(fromMultibase(secretKeyMultibase));
    }

    /**
     * @param secretKeyFile a file holding the secret key multibase (one line)
     * @throws VcDataIntegrityCryptographicSuiteException if the file can't be read or isn't a composite secret key
     */
    public MlDsa65Ed25519JcsPqeidVcDataIntegrityCryptographicSuite(Path secretKeyFile) throws VcDataIntegrityCryptographicSuiteException {
        this(fromMultibase(readSecret(secretKeyFile)));
    }

    private MlDsa65Ed25519JcsPqeidVcDataIntegrityCryptographicSuite(CompositeSigningKey signingKey) {
        this.signingKey = signingKey;
        this.cryptoSuite = MlDsa65Ed25519JcsPqeidCryptosuite.Companion.fromSigningKey(signingKey);
    }

    private static CompositeSigningKey fromMultibase(String secretKeyMultibase) throws VcDataIntegrityCryptographicSuiteException {
        try {
            return CompositeSigningKey.Companion.fromMultibase(secretKeyMultibase.trim());
        } catch (DidSidekicksException e) {
            throw new VcDataIntegrityCryptographicSuiteException(e);
        }
    }

    private static String readSecret(Path secretKeyFile) throws VcDataIntegrityCryptographicSuiteException {
        try {
            return Files.readString(secretKeyFile, StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new VcDataIntegrityCryptographicSuiteException(e);
        }
    }

    /**
     * @return the composite secret key multibase. <b>Secret</b>: store it with owner-only file permissions.
     */
    public String getSecretKeyMultibase() {
        return signingKey.toMultibase();
    }

    /**
     * @return the composite public multikey (private-use multicodec 0x300001), as used in {@code updateKeys}
     */
    @Override
    public String getVerificationKeyMultibase() {
        return signingKey.getVerifyingKey().toMultibase();
    }

    /**
     * Not supported: this suite only produces complete data integrity proofs, see
     * {@link #addProof(String, String, String, ZonedDateTime)} (the method is deprecated upstream for the same reason).
     */
    @Override
    @Deprecated
    public byte[] generateSignature(byte[] message) {
        throw new UnsupportedOperationException("use addProof: " + MLDSA65_ED25519_JCS_PQEID + " signs complete proofs only");
    }

    @Override
    public boolean isKeyMultibaseInSet(Set<String> multibaseEncodedKeys) {
        return multibaseEncodedKeys.contains(getVerificationKeyMultibase());
    }

    /**
     * The {@code mldsa65-ed25519-jcs-pqeid} proof: the {@code eddsa-jcs-2022} steps, signed with the composite key.
     * The proof's {@code verificationMethod} is {@code did:key:<multikey>#<multikey>}, as for {@code eddsa-jcs-2022}.
     */
    @Override
    public String addProof(String unsecuredDocument,
                           String challenge,
                           String proofPurpose,
                           ZonedDateTime dateTime)
            throws VcDataIntegrityCryptographicSuiteException {

        JsonObject unsecuredDocumentJsonObject;
        try {
            unsecuredDocumentJsonObject = JsonParser.parseString(unsecuredDocument).getAsJsonObject();
        } catch (JsonSyntaxException | IllegalStateException ex) {
            throw new VcDataIntegrityCryptographicSuiteException(ex);
        }

        // as in eddsa-jcs-2022: if unsecuredDocument.@context is present, set proof.@context to it
        var ctx = unsecuredDocumentJsonObject.get("@context");
        List<String> context = new ArrayList<>();
        if (ctx != null && ctx.isJsonArray()) {
            ctx.getAsJsonArray().forEach(jsonElement -> context.add(jsonElement.getAsString()));
        }

        var multikey = getVerificationKeyMultibase();
        try {
            return this.cryptoSuite.addProof(
                    unsecuredDocument,
                    CryptoSuiteProofOptions.Companion.newMldsa65Ed25519JcsPqeid(
                            DateTimeFormatter.ISO_INSTANT.format(dateTime.truncatedTo(ChronoUnit.SECONDS)),
                            "did:key:" + multikey + '#' + multikey,
                            proofPurpose,
                            context.isEmpty() ? null : context,
                            challenge
                    )
            );
        } catch (DidSidekicksException e) {
            throw new VcDataIntegrityCryptographicSuiteException(e);
        }
    }
}
