package ch.admin.bj.swiyu.didtoolbox;

import ch.admin.bj.swiyu.didtoolbox.jcommander.CreateDidLogCommand;
import ch.admin.bj.swiyu.didtoolbox.jcommander.VerificationMethodParameters;
import ch.admin.bj.swiyu.didtoolbox.model.DidMethodEnum;
import com.beust.jcommander.JCommander;
import com.beust.jcommander.internal.Console;
import com.google.gson.JsonParser;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.net.URI;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * PQEID: {@code create -m did:webvh:1.0-pqeid} produces a fully hybrid DID, or refuses: no silent classical defaults.
 */
@SuppressWarnings("PMD")
class JCommanderRunnerPqeidTest extends AbstractUtilTestBase {

    private static final Path COMPOSITE_PUB = Path.of("src/test/data/composite-key-01.pub");
    private static final Path EC_PUB = Path.of("src/test/data/assert-key-01.pub");

    private StringBuilder output;
    private final JCommander.Builder jCommanderBuilder = JCommander.newBuilder().console(new Console() {
        @Override
        public void print(CharSequence charSequence) {
            // not used
        }

        @Override
        public void println(CharSequence charSequence) {
            output.append(charSequence);
        }

        @Override
        public char[] readPassword(boolean echoInput) {
            return new char[0];
        }
    });

    @BeforeEach
    void setUp() {
        output = new StringBuilder();
    }

    private CreateDidLogCommand pqeidCommand() throws Exception {
        var command = new CreateDidLogCommand();
        command.methodVersion = DidMethodEnum.WEBVH_1_0_PQEID;
        command.forceOverwrite = true;
        command.identifierRegistryUrl = URL.of(new URI(TEST_DID_URL), null);
        return command;
    }

    private void run(CreateDidLogCommand command, Path tmpDir) throws Exception {
        new JCommanderRunner(jCommanderBuilder.addCommand(CreateDidLogCommand.COMMAND_NAME, command).build(),
                CreateDidLogCommand.COMMAND_NAME, tmpDir.toString()).runCreateDidLogCommand(command);
    }

    private static VerificationMethodParameters key(String kid, Path pub) throws Exception {
        return new VerificationMethodParameters(kid, JwkUtils.loadPublicJWKasJSON(pub, kid));
    }

    @Test
    void missingVerificationMethodsAreRefused_noDefaultEcKeyIsGenerated(@TempDir Path tmpDir) throws Exception {
        var command = pqeidCommand(); // neither --assert nor --auth

        var ex = assertThrows(JCommanderRunner.CommandException.class, () -> run(command, tmpDir));
        assertTrue(ex.getMessage().contains("--assert"), ex.getMessage());
        assertTrue(output.isEmpty());
        // nothing was generated, in particular no classical assert-key-01 / auth-key-01
        assertFalse(Files.exists(tmpDir.resolve("assert-key-01")));
        assertFalse(Files.exists(tmpDir.resolve("id_mldsa65_ed25519")));
    }

    @Test
    void classicalVerificationMethodIsRefused(@TempDir Path tmpDir) throws Exception {
        var command = pqeidCommand();
        command.assertionMethodKeys = Set.of(key("assert-key-01", EC_PUB)); // EC P-256
        command.authenticationKeys = Set.of(key("auth-key-01", COMPOSITE_PUB));

        var ex = assertThrows(JCommanderRunner.CommandException.class, () -> run(command, tmpDir));
        assertTrue(ex.getMessage().contains("kty=EC"), ex.getMessage());
        assertTrue(output.isEmpty());
    }

    @Test
    void compositeVerificationMethodsGiveAFullyHybridDid(@TempDir Path tmpDir) throws Exception {
        var command = pqeidCommand();
        command.assertionMethodKeys = Set.of(key("assert-key-01", COMPOSITE_PUB));
        command.authenticationKeys = Set.of(key("auth-key-01", COMPOSITE_PUB));

        assertDoesNotThrow(() -> run(command, tmpDir));

        var entry = JsonParser.parseString(output.toString()).getAsJsonObject();
        assertEquals("did:webvh:1.0-pqeid", entry.getAsJsonObject("parameters").get("method").getAsString());
        entry.getAsJsonObject("state").getAsJsonArray("verificationMethod").forEach(vm -> {
            var jwk = vm.getAsJsonObject().getAsJsonObject("publicKeyJwk");
            assertEquals("AKP", jwk.get("kty").getAsString());
            assertEquals("ML-DSA-65-ES256", jwk.get("alg").getAsString());
        });
        // the composite update key is stored, and no Ed25519 one
        var dir = tmpDir;
        assertTrue(Files.exists(dir.resolve("id_mldsa65_ed25519")));
        assertTrue(Files.exists(dir.resolve("id_mldsa65_ed25519.pub")));
        assertFalse(Files.exists(dir.resolve("id_ed25519")));
    }

    @Test
    void standardVersionStillGeneratesItsDefaultKeys(@TempDir Path tmpDir) throws Exception {
        var command = pqeidCommand();
        command.methodVersion = DidMethodEnum.WEBVH_1_0; // upstream behaviour unchanged

        assertDoesNotThrow(() -> run(command, tmpDir));
        assertEquals("did:webvh:1.0", JsonParser.parseString(output.toString()).getAsJsonObject()
                .getAsJsonObject("parameters").get("method").getAsString());
    }
}
