package ch.admin.bj.swiyu.didtoolbox;

import com.google.gson.JsonParser;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.MLDSAKey;
import com.nimbusds.jose.jwk.gen.MLDSAKeyGenerator;
import com.nimbusds.jose.JWSAlgorithm;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.util.io.pem.PemObject;

import java.io.*;
import java.nio.file.*;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.InvalidKeySpecException;

/**
 * The {@link JwkUtils} is a simple helper for the purpose of <a href="https://datatracker.ietf.org/doc/html/rfc7517#appendix-A.1">JWKS</a>
 * key pair generation
 */
public final class JwkUtils {

    private JwkUtils() {
    }

    /**
     * Loads a public EC P-256 key from the specified PEM file and returns its JWK JSON representation
     *
     * @param ecPublicPemFile the EC P-256 public key in PEM format
     * @param kid             the ID (kid) of the JWK that can be used to match this key.
     *                        A regular case-sensitive string featuring no URIs reserved characters is expected.
     *                        Otherwise, {@link IllegalArgumentException} is thrown
     * @return JSON object string representation of the public JWK
     * @throws IOException             if the file couldn't be read
     * @throws InvalidKeySpecException if the given key specification is inappropriate for the EC key factory to produce a public key
     * @deprecated Use {@link #loadECPublicJWKasJSON(Path, String)} instead
     */
    @Deprecated(since = "1.8.0")
    public static String loadECPublicJWKasJSON(File ecPublicPemFile, String kid) throws IOException, InvalidKeySpecException {
        return loadECPublicJWKasJSON(ecPublicPemFile.toPath(), kid);
    }

    /**
     * Loads a public EC P-256 key from the specified PEM file and returns its JWK JSON representation
     *
     * @param ecPublicPemPath to file featuring an EC P-256 public key in PEM format
     * @param kid             the ID (kid) of the JWK that can be used to match this key.
     *                        A regular case-sensitive string featuring no URIs reserved characters is expected.
     *                        Otherwise, {@link IllegalArgumentException} is thrown
     * @return JSON object string representation of the public JWK
     * @throws IOException             if the file couldn't be read
     * @throws InvalidKeySpecException if the given key specification is inappropriate for the EC key factory to produce a public key
     */
    public static String loadECPublicJWKasJSON(Path ecPublicPemPath, String kid) throws IOException, InvalidKeySpecException {
        if (!Files.isReadable(ecPublicPemPath)) {
            throw new FileNotFoundException(String.format("The file '%s' doesn't exist.", ecPublicPemPath));
        }

        if (!kid.matches("[a-zA-Z0-9~._-]+")) {
            throw new IllegalArgumentException(String.format("The supplied key ID (kid) of the JWK '%s' must be a regular case-sensitive string featuring no URIs reserved characters", kid));
        }

        var publicKey = (ECPublicKey) PemUtils.parsePemPublicKey(Files.newBufferedReader(ecPublicPemPath));

        return new ECKey.Builder(Curve.P_256, publicKey).keyID(kid).build().toPublicJWK().toJSONString();
    }

    /**
     * Loads a public key from the specified PEM file and returns its JWK JSON representation, dispatching
     * on the key's actual type: EC P-256 (see {@link #loadECPublicJWKasJSON(Path, String)}) or ML-DSA
     * (PQEID: any of ML-DSA-44/65/87, represented as an AKP JWK).
     * <p>
     * Unlike {@link #loadECPublicJWKasJSON(Path, String)}, this does not require the PEM file to contain
     * an EC key - {@link PemUtils#parsePemPublicKey(Reader)} already determines the key's algorithm from
     * its {@code SubjectPublicKeyInfo}, so only the JWK-building step below needed to stop assuming EC.
     *
     * @param publicPemPath to file featuring an EC P-256 or ML-DSA public key in PEM format
     * @param kid           the ID (kid) of the JWK that can be used to match this key.
     *                      A regular case-sensitive string featuring no URIs reserved characters is expected.
     *                      Otherwise, {@link IllegalArgumentException} is thrown
     * @return JSON object string representation of the public JWK
     * @throws IOException             if the file couldn't be read
     * @throws InvalidKeySpecException if the given key specification is inappropriate for the key factory to produce a public key
     */
    public static String loadPublicJWKasJSON(Path publicPemPath, String kid) throws IOException, InvalidKeySpecException {
        if (!Files.isReadable(publicPemPath)) {
            throw new FileNotFoundException(String.format("The file '%s' doesn't exist.", publicPemPath));
        }

        if (!kid.matches("[a-zA-Z0-9~._-]+")) {
            throw new IllegalArgumentException(String.format("The supplied key ID (kid) of the JWK '%s' must be a regular case-sensitive string featuring no URIs reserved characters", kid));
        }

        PublicKey publicKey = PemUtils.parsePemPublicKey(Files.newBufferedReader(publicPemPath));

        if (publicKey instanceof ECPublicKey ecPublicKey) {
            return new ECKey.Builder(Curve.P_256, ecPublicKey).keyID(kid).build().toPublicJWK().toJSONString();
        }

        try {
            // PQEID: MLDSAKey infers the ML-DSA parameter set (44/65/87) from the public key itself.
            return new MLDSAKey.Builder(publicKey).keyID(kid).build().toPublicJWK().toJSONString();
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Unsupported public key type: " + publicKey.getClass().getName(), e);
        }
    }

    /**
     * PQEID: generates a new ML-DSA-44 key pair (in <a href="https://datatracker.ietf.org/doc/html/rfc7517#appendix-A.1">JWKS</a>
     * format, as an AKP JWK). If {@code keyPairPemFile} is supplied, the key pair is exported in
     * <a href="https://en.wikipedia.org/wiki/Privacy-Enhanced_Mail">PEM</a> format (PKCS8 private key,
     * X.509 SubjectPublicKeyInfo public key) - mirrors {@link #generatePublicEC256(String, File, boolean)}.
     *
     * @param kid            the ID of the JWK, that can be used to match a specific key
     * @param keyPairPemFile if not {@code null}, the file where a generated key pair will be stored
     *                       (in PEM format)
     * @param forceOverwrite the flag controlling whether the existing PEM files should be overwritten or not
     * @return a new public ML-DSA-44 JWK (in JSON format).
     * @throws IOException if persisting a key pair fails
     */
    public static String generatePublicMLDSA44(String kid, File keyPairPemFile, boolean forceOverwrite) throws IOException {

        MLDSAKey mldsaJwk;
        try {
            mldsaJwk = new MLDSAKeyGenerator(JWSAlgorithm.ML_DSA_44).keyID(kid).generate();
        } catch (JOSEException e) {
            throw new IllegalArgumentException(e);
        }

        if (keyPairPemFile != null) {

            if (!keyPairPemFile.exists() || forceOverwrite) {

                createPrivateFile(keyPairPemFile, forceOverwrite);

                try {
                    try (Writer w = Files.newBufferedWriter(keyPairPemFile.toPath());
                         JcaPEMWriter pemWriter = new JcaPEMWriter(w)) {
                        // as specified by https://www.rfc-editor.org/rfc/rfc5208 (PKCS8)
                        pemWriter.writeObject(new PemObject("PRIVATE KEY", mldsaJwk.toPrivateKey().getEncoded()));
                    }

                    try (JcaPEMWriter pemWriterPub = new JcaPEMWriter(Files.newBufferedWriter(Path.of(keyPairPemFile.getPath() + ".pub")))) {
                        pemWriterPub.writeObject(new PemObject("PUBLIC KEY", mldsaJwk.toPublicKey().getEncoded()));
                    }
                } catch (JOSEException e) {
                    throw new IllegalArgumentException(e);
                }

            } else {
                throw new IOException("The PEM file(s) exist(s) already and will remain intact until overwrite mode is engaged: " + keyPairPemFile.getPath());
            }
        }

        var publicJwkJsonObject = JsonParser.parseString(mldsaJwk.toPublicJWK().toJSONString()).getAsJsonObject();

        return publicJwkJsonObject.toString();
    }

    /**
     * Generates a new key pair (in <a href="https://datatracker.ietf.org/doc/html/rfc7517#appendix-A.1">JWKS</a> format)
     * using standard digital signature algorithm
     * <a href="https://datatracker.ietf.org/doc/html/rfc7518#section-3.4">ECDSA using P-256 curve and SHA-256 hash function</a>.
     * If {@code keyPairPemFile} is supplied, the key pair is exported in
     * <a href="https://en.wikipedia.org/wiki/Privacy-Enhanced_Mail">PEM</a> format.
     * Needless to say, the helper ensures the private key file access is restricted to current user only.
     *
     * @param kid            the ID of the JWK, that can be used to match a specific key
     * @param keyPairPemFile if not {@code null}, the file where a generated key pair will be stored
     *                       (in <a href="https://en.wikipedia.org/wiki/Privacy-Enhanced_Mail">PEM</a> format)
     * @param forceOverwrite the flag controlling whether the existing PEM files should be overwritten or not
     * @return a new public EC JWK (in JSON format).
     * @throws IOException if persisting a key pair fails
     */
    public static String generatePublicEC256(String kid, File keyPairPemFile, boolean forceOverwrite) throws IOException {

        KeyPairGenerator keyPairGenerator;
        try {
            keyPairGenerator = KeyPairGenerator.getInstance("EC", BouncyCastleProviderSingleton.getInstance());
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalArgumentException(e);
        }

        keyPairGenerator.initialize(256);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        StringWriter stringWriter = new StringWriter();
        try (JcaPEMWriter pemWriter = new JcaPEMWriter(stringWriter)) {
            pemWriter.writeObject(keyPair); // CAUTION The whole key pair is expected to be written here, not only the private key
        }
        String keyPairPem = stringWriter.toString();

        stringWriter = new StringWriter();
        try (JcaPEMWriter pemWriter = new JcaPEMWriter(stringWriter)) {
            pemWriter.writeObject(keyPair.getPublic());
        }
        String publicKeyPem = stringWriter.toString();

        JWK publicJwk;
        try {
            // CAUTION By using com.nimbusds.jose.jwk.gen.ECKeyGenerator (see https://connect2id.com/products/nimbus-jose-jwt/examples/jws-with-ec-signature)
            //         to create a com.nimbusds.jose.jwk.JWK object you may end up having incomplete EC PRIVATE KEY export later on.
            publicJwk = JWK.parseFromPEMEncodedObjects(publicKeyPem).toECKey();
        } catch (JOSEException e) {
            throw new IllegalArgumentException(e);
        }

        var publicJwkJsonObject = JsonParser.parseString(publicJwk.toJSONString()).getAsJsonObject();
        publicJwkJsonObject.addProperty("kid", kid);

        if (keyPairPemFile != null) {

            if (!keyPairPemFile.exists() || forceOverwrite) {

                createPrivateFile(keyPairPemFile, forceOverwrite);

                try (Writer w = Files.newBufferedWriter(keyPairPemFile.toPath())) {
                    w.write(keyPairPem);
                    w.flush();
                }

                // Creates (keyPairPemFile || ".pub") file
                exportEcPublicKeyToPem(publicJwk, keyPairPemFile);

            } else {
                throw new IOException("The PEM file(s) exist(s) already and will remain intact until overwrite mode is engaged: " + keyPairPemFile.getPath());
            }
        }

        return publicJwkJsonObject.toString();
    }

    /**
     * Wrapper for {@link FilesPrivacy#createPrivateFile(Path, boolean)}
     */
    private static void createPrivateFile(File keyPairPemFile, boolean forceOverwrite) throws IOException {
        try {
            // CAUTION A private key file MUST always be created with appropriate file permissions i.e. with access restricted to the current user only
            FilesPrivacy.createPrivateFile(keyPairPemFile.toPath(), forceOverwrite); // may throw FileAlreadyExistsException, SecurityException etc.
        } catch (DirectoryNotEmptyException | AccessDeniedException ex) {
            // the file must not exist and write access must be already granted
            throw new IllegalArgumentException(ex); // it should be a file, not a directory
        } catch (FileAlreadyExistsException ex) {
            if (!keyPairPemFile.exists()) {
                throw new IllegalArgumentException(ex);
            }
            throw ex;
        } catch (Throwable thr) { // NOPMD AvoidCatchingGenericException
            throw new IOException("The private key PEM file " + keyPairPemFile.getPath() + " could not be (re)created with restricted access due to: " + thr.getMessage(), thr);
        }
    }

    /**
     * PEM export helper.
     */
    private static void exportEcPublicKeyToPem(JWK jwk, File keyPairPemFile) throws IOException {
        try (var pemWriterPub = new JcaPEMWriter(Files.newBufferedWriter(Path.of(keyPairPemFile.getPath() + ".pub")))) {
            // as specified by https://www.rfc-editor.org/rfc/rfc5208
            pemWriterPub.writeObject(new PemObject("PUBLIC KEY", jwk.toECKey().toPublicKey().getEncoded()));
            pemWriterPub.flush();
        } catch (JOSEException e) {
            throw new IllegalArgumentException(e);
        }
    }
}
