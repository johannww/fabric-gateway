/*
 * Copyright 2019 IBM All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package org.hyperledger.fabric.client.identity;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.util.Date;
import java.util.Locale;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcECContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

public final class X509Credentials {
    private static final Provider BC_PROVIDER = new BouncyCastleProvider();

    private final X509Certificate certificate;
    private final PrivateKey privateKey;

    /**
     * Create credentials using a P-256 curve.
     */
    public X509Credentials() {
        this("EC", "P-256");
    }

    public X509Credentials(String keyAlgorithm, String curveName) {
        KeyPair keyPair = generateKeyPair(keyAlgorithm, curveName);
        certificate = generateCertificate(keyPair);
        privateKey = keyPair.getPrivate();
    }

    private KeyPair generateKeyPair(String keyAlgorithm, String curveName) {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance(keyAlgorithm, BC_PROVIDER);
            if (keyAlgorithm == "EC" && curveName.length() > 0) {
                AlgorithmParameterSpec curveParam = new ECGenParameterSpec(curveName);
                generator.initialize(curveParam);
            }
            return generator.generateKeyPair();
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
            throw new RuntimeException(e);
        }
    }

    private X509Certificate generateCertificate(KeyPair keyPair) {
        X500Name dnName = new X500Name("CN=John Doe");
        Date validityBeginDate = new Date(System.currentTimeMillis() - 24L * 60 * 60 * 1000); // Yesterday
        Date validityEndDate = new Date(System.currentTimeMillis() + 2L * 365 * 24 * 60 * 60 * 1000); // 2 years from now
        SubjectPublicKeyInfo subPubKeyInfo = SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded());
        X509v3CertificateBuilder builder = new X509v3CertificateBuilder(
                dnName,
                BigInteger.valueOf(System.currentTimeMillis()),
                validityBeginDate,
                validityEndDate,
                Locale.getDefault(),
                dnName,
                subPubKeyInfo);

        AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find("SHA256WithRSAEncryption");
        AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);

        try {
            ContentSigner contentSigner = null;
            if (keyPair.getPrivate().getAlgorithm() == "EC")
                contentSigner = new BcECContentSignerBuilder(sigAlgId, digAlgId)
                        .build(PrivateKeyFactory.createKey(keyPair.getPrivate().getEncoded()));
            else if (keyPair.getPrivate().getAlgorithm() == "Ed25519"){
                contentSigner = new JcaContentSignerBuilder("Ed25519")
                    .setProvider(BC_PROVIDER)
                    .build(keyPair.getPrivate());
            }
            X509CertificateHolder holder = builder.build(contentSigner);
            return new JcaX509CertificateConverter().getCertificate(holder);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        } catch (OperatorCreationException | CertificateException e) {
            throw new RuntimeException(e);
        }
    }

    public X509Certificate getCertificate() {
        return certificate;
    }

    public String getCertificatePem() {
        return Identities.toPemString(certificate);
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public String getPrivateKeyPem() {
        return Identities.toPemString(privateKey);
    }
}
