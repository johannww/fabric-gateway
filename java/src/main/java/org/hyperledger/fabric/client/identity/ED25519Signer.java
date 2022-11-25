/*
 * Copyright 2020 IBM All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package org.hyperledger.fabric.client.identity;

import java.security.GeneralSecurityException;
import java.security.Provider;
import java.security.Signature;

import org.bouncycastle.jcajce.interfaces.EdDSAPrivateKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

final class ED25519Signer implements Signer {

    private static final Provider PROVIDER = new BouncyCastleProvider();
    private static final String ALGORITHM_NAME = "Ed25519";

    private final EdDSAPrivateKey privateKey;

    ED25519Signer(final EdDSAPrivateKey privateKey) {
        this.privateKey = privateKey;
    }

    @Override
    public byte[] sign(final byte[] message) throws GeneralSecurityException {
        byte[] rawSignature = generateSignature(message);
        return rawSignature;
    }

    private byte[] generateSignature(final byte[] message) throws GeneralSecurityException {
        Signature signer = Signature.getInstance(ALGORITHM_NAME, PROVIDER);
        signer.initSign(privateKey);
        signer.update(message);
        return signer.sign();
    }
}
