package ch.admin.bj.swiyu.didtoolbox.context;

import ch.admin.bj.swiyu.didtoolbox.TdwCreator;
import ch.admin.bj.swiyu.didtoolbox.TdwDeactivator;
import ch.admin.bj.swiyu.didtoolbox.TdwUpdater;
import ch.admin.bj.swiyu.didtoolbox.vc_data_integrity.MlDsa65Ed25519JcsPqeidVcDataIntegrityCryptographicSuite;
import ch.admin.bj.swiyu.didtoolbox.webvh.WebVerifiableHistoryCreator;
import ch.admin.bj.swiyu.didtoolbox.webvh.WebVerifiableHistoryDeactivator;
import ch.admin.bj.swiyu.didtoolbox.webvh.WebVerifiableHistoryUpdater;

/**
 * The factory delivering all possible strategies in regard to DID log manipulation, regardless of DID method.
 */
final class DidLogStrategyFactory {

    private DidLogStrategyFactory() {
    }

    static DidLogCreatorStrategy getCreatorStrategy(DidLogCreatorContext ctx) throws DidLogCreatorStrategyException {

        switch (ctx.getDidMethod()) {
            case TDW_0_3 -> {

                if (!ctx.allNextKeyHashesDidMethodParameter().isEmpty()) {
                    throw new IllegalArgumentException(String.format("The key pre-rotation is currently not supported for %s DID logs", ctx.getDidMethod()));
                }

                return TdwCreator.builder(ctx.getCryptoSuite())
                        .assertionMethods(ctx.allAssertionMethods())
                        .authentications(ctx.allAuthentications())
                        // Using alternative and more potent method to supply the parameter.
                        // Eventually, all supplied keys are combined and their distinct values are taken.
                        .updateKeysDidMethodParameter(ctx.allUpdateKeysDidMethodParameter())
                        .build();
            }
            case WEBVH_1_0, WEBVH_1_0_PQEID -> {
                // PQEID: the requested version and the suite must agree (hybrid suite <=> did:webvh:1.0-pqeid)
                var hybridSuite = ctx.getCryptoSuite() instanceof MlDsa65Ed25519JcsPqeidVcDataIntegrityCryptographicSuite;
                if (hybridSuite != ctx.getDidMethod().isPqeid()) {
                    throw new IllegalArgumentException(String.format(
                            "%s requires %s log proofs", ctx.getDidMethod(),
                            ctx.getDidMethod().isPqeid() ? "mldsa65-ed25519-jcs-pqeid" : "eddsa-jcs-2022"));
                }
                return WebVerifiableHistoryCreator.builder(ctx.getCryptoSuite())
                        .assertionMethods(ctx.allAssertionMethods())
                        .authentications(ctx.allAuthentications())
                        // Using alternative and more potent method to supply the parameter.
                        // Eventually, all supplied keys are combined and their distinct values are taken.
                        .updateKeysDidMethodParameter(ctx.allUpdateKeysDidMethodParameter())
                        // Using alternative and more potent method to supply the parameter.
                        // Eventually, all supplied keys are combined and their distinct values are taken.
                        .nextKeyHashesDidMethodParameter(ctx.allNextKeyHashesDidMethodParameter())
                        .build();
            }
            default -> throw new IllegalArgumentException("The supplied DID log features an unsupported DID method");
        }
    }

    static DidLogUpdaterStrategy getUpdaterStrategy(DidLogUpdaterContext ctx) throws DidLogUpdaterStrategyException {
        switch (ctx.getDidMethod()) {
            case TDW_0_3 -> {

                if (!ctx.allNextKeyHashesDidMethodParameter().isEmpty()) {
                    throw new IllegalArgumentException(String.format("The key pre-rotation is currently not supported for %s DID logs", ctx.getDidMethod()));
                }

                return TdwUpdater.builder(ctx.getCryptoSuite())
                        .assertionMethods(ctx.allAssertionMethods())
                        .authentications(ctx.allAuthentications())
                        // Using alternative and more potent method to supply the parameter.
                        // Eventually, all supplied keys are combined and their distinct values are taken.
                        .updateKeysDidMethodParameter(ctx.allUpdateKeysDidMethodParameter())
                        // CAUTION Not implemented yet:
                        // .nextKeys(ctx.getNextKeys())
                        .build();
            }
            case WEBVH_1_0 -> {
                return WebVerifiableHistoryUpdater.builder(ctx.getCryptoSuite())
                        .assertionMethods(ctx.allAssertionMethods())
                        .authentications(ctx.allAuthentications())
                        // Using alternative and more potent method to supply the parameter.
                        // Eventually, all supplied keys are combined and their distinct values are taken.
                        .updateKeysDidMethodParameter(ctx.allUpdateKeysDidMethodParameter())
                        // Using alternative and more potent method to supply the parameter.
                        // Eventually, all supplied keys are combined and their distinct values are taken.
                        .nextKeyHashesDidMethodParameter(ctx.allNextKeyHashesDidMethodParameter())
                        .build();
            }
            default -> throw new IllegalArgumentException("The supplied DID log features an unsupported DID method");
        }
    }

    static DidLogDeactivatorStrategy getDeactivatorStrategy(DidLogDeactivatorContext ctx) {
        switch (ctx.getDidMethod()) {
            case TDW_0_3 -> {
                return TdwDeactivator.builder(ctx.getCryptoSuite())
                        .build();
            }
            case WEBVH_1_0 -> {
                return WebVerifiableHistoryDeactivator.builder(ctx.getCryptoSuite())
                        .build();
            }
            default -> throw new IllegalArgumentException("The supplied DID log features an unsupported DID method");
        }
    }
}
