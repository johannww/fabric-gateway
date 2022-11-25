/*
 * Copyright 2019 IBM All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package org.hyperledger.fabric.client.identity;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.hyperledger.fabric.client.Hash;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

public final class SignerTest {
    private static final X509Credentials CREDENTIALS = new X509Credentials();
    private static final Provider PROVIDER = new BouncyCastleProvider();
    private static final byte[] MESSAGE = "MESSAGE".getBytes(StandardCharsets.UTF_8);
    private static final byte[] DIGEST = Hash.sha256(MESSAGE);

    private static void assertValidECSignature(X509Certificate certificate, final byte[] signature) throws GeneralSecurityException {
        Signature verifier = Signature.getInstance("SHA256withECDSA", PROVIDER);
        verifier.initVerify(certificate);
        verifier.update(MESSAGE);
        assertThat(verifier.verify(signature))
                .withFailMessage("invalid signature: %s", Arrays.toString(signature))
                .isTrue();
    }

    private static void assertValidEd25519Signature(X509Certificate certificate, final byte[] signature) throws GeneralSecurityException {
        Signature verifier = Signature.getInstance("Ed25519", PROVIDER);
        KeyFactory ed25519Fact = KeyFactory.getInstance("Ed25519", PROVIDER);
        PublicKey pub = ed25519Fact.generatePublic(new X509EncodedKeySpec(certificate.getPublicKey().getEncoded()));
        verifier.initVerify(pub);
        verifier.update(MESSAGE);
        assertThat(verifier.verify(signature))
                .withFailMessage("invalid signature: %s", Arrays.toString(signature))
                .isTrue();
    }

    @Test
    void new_signer_from_unsupported_private_key_type_throws_IllegalArgumentException() throws NoSuchAlgorithmException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("DSA", new BouncyCastleProvider());
        generator.initialize(2048);
        KeyPair keyPair = generator.generateKeyPair();

        assertThatThrownBy(() -> Signers.newPrivateKeySigner(keyPair.getPrivate()))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void sign_with_P256_key() throws GeneralSecurityException {
        Signer signer = Signers.newPrivateKeySigner(CREDENTIALS.getPrivateKey());
        byte[] signature = signer.sign(DIGEST);

        assertValidECSignature(CREDENTIALS.getCertificate(), signature);
    }

    @Test
    void sign_null_digest_throws_NullPointerException() {
        Signer signer = Signers.newPrivateKeySigner(CREDENTIALS.getPrivateKey());

        assertThatThrownBy(() -> signer.sign(null))
            .isInstanceOf(NullPointerException.class);
    }

    @Test
    void sign_with_P384_key() throws GeneralSecurityException {
        X509Credentials credentials = new X509Credentials("EC", "P-384");
        Signer signer = Signers.newPrivateKeySigner(credentials.getPrivateKey());
        byte[] signature = signer.sign(DIGEST);

        assertValidECSignature(credentials.getCertificate(), signature);
    }

    @Test
    void sign_with_ED25519_key() throws GeneralSecurityException {
        X509Credentials credentials = new X509Credentials("Ed25519", "");
        Signer signer = Signers.newPrivateKeySigner(credentials.getPrivateKey());
        byte[] signature = signer.sign(MESSAGE);

        assertValidEd25519Signature(credentials.getCertificate(), signature);
    }
}
