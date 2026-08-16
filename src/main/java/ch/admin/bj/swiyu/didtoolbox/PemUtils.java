package ch.admin.bj.swiyu.didtoolbox;

import ch.admin.eid.did_sidekicks.DidSidekicksException;
import ch.admin.eid.did_sidekicks.Ed25519VerifyingKey;
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.Reader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

public final class PemUtils {

    private PemUtils() {
    }

    /**
     * Loads a PEM key from the supplied file.
     *
     * @param pemFile to read PEM key from
     * @return the PEM key as byte array
     * @throws FileNotFoundException in case of inappropriate {@code pemFile} parameter value
     * @throws IOException           in case of a parse error
     */
    public static byte[] readPEMFile(File pemFile) throws IOException {

        if (!pemFile.isFile()) {
            throw new FileNotFoundException(String.format("The file '%s' doesn't exist.", pemFile.getAbsolutePath()));
        }

        return readPemObject(Files.newBufferedReader(pemFile.toPath()));
    }

    static KeyPair parsePemKeyPairFile(File pemFile) throws IOException {

        if (!pemFile.isFile()) {
            throw new FileNotFoundException(String.format("The file '%s' doesn't exist.", pemFile.getAbsolutePath()));
        }

        return parsePemKeyPair(Files.newBufferedReader(pemFile.toPath()));
    }

    static byte[] readPemObject(Reader pemKeyReader) throws IOException {
        PemReader reader = new PemReader(pemKeyReader);
        PemObject pemObject = reader.readPemObject();
        byte[] content = pemObject.getContent();
        reader.close();
        return content;
    }

    public static KeyPair parsePemKeyPair(Reader pemKeyPairReader) throws IOException {
        final PEMParser parser = new PEMParser(pemKeyPairReader);
        var pemObj = parser.readObject();

        // if EC private key given, it arrives here as a keypair
        if (pemObj instanceof PEMKeyPair) {
            return convertWithBcFallback(new JcaPEMKeyConverter(), c -> c.getKeyPair((PEMKeyPair) pemObj));
        }

        throw new IllegalArgumentException("The supplied reader features no PEM-encoded key pair");
    }

    static PrivateKey parsePemPrivateKey(Reader pemPrivateKeyReader) throws IOException {
        final PEMParser parser = new PEMParser(pemPrivateKeyReader);
        var pemObj = parser.readObject();

        if (pemObj instanceof PrivateKeyInfo) {
            return convertWithBcFallback(new JcaPEMKeyConverter(), c -> c.getPrivateKey((PrivateKeyInfo) pemObj));
        }

        throw new IllegalArgumentException("The supplied reader features no PEM-encoded private key");
    }

    public static PublicKey parsePemPublicKey(Reader pemPublicKeyReader) throws IOException {
        final PEMParser parser = new PEMParser(pemPublicKeyReader);
        var pemObj = parser.readObject();

        if (pemObj instanceof SubjectPublicKeyInfo) {
            return convertWithBcFallback(new JcaPEMKeyConverter(), c -> c.getPublicKey((SubjectPublicKeyInfo) pemObj));
        }

        throw new IllegalArgumentException("The supplied reader features no PEM-encoded public key");
    }

    @FunctionalInterface
    private interface PemConversion<T> {
        T apply(JcaPEMKeyConverter converter) throws PEMException;
    }

    /**
     * PQEID: tries the default (JVM built-in) provider first, preserving prior behaviour for
     * algorithms the JVM already supports natively (e.g. EC, via the JDK's own SunEC provider) -
     * some consumers (e.g. nimbus-jose-jwt's ECDSASigner) require that specific key implementation
     * for their own Signature/KeyFactory calls to succeed, and fail against BouncyCastle's own EC
     * key implementation. Falls back to BouncyCastle explicitly only if the default provider can't
     * handle the key's algorithm (e.g. ML-DSA, for which there is no built-in JVM provider).
     */
    private static <T> T convertWithBcFallback(JcaPEMKeyConverter converter, PemConversion<T> conversion) throws IOException {
        try {
            return conversion.apply(converter);
        } catch (PEMException e) {
            return conversion.apply(converter.setProvider(BouncyCastleProviderSingleton.getInstance()));
        }
    }

    public static String readEd25519PublicKeyPemFileToMultibase(Path publicKeyPemFile) throws DidSidekicksException {

        try (var publicKey = Ed25519VerifyingKey.Companion.readPublicKeyPemFile(publicKeyPemFile.toString())) {
            return publicKey.toMultibase();
        }
    }

    static String fromEd25519PublicKeyPemToMultibase(String pemPublicKey) throws DidSidekicksException {

        try (var publicKey = Ed25519VerifyingKey.Companion.fromPublicKeyPem(pemPublicKey)) {
            return publicKey.toMultibase();
        }
    }
}