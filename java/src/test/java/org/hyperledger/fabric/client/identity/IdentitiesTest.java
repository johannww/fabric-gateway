/*
 * Copyright 2020 IBM All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package org.hyperledger.fabric.client.identity;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.hyperledger.fabric.client.TestUtils;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

public class IdentitiesTest {
    private static final TestUtils testUtils = TestUtils.getInstance();
    private static final Provider BC_PROVIDER = new BouncyCastleProvider();

    private final X509Credentials credentials = new X509Credentials();
    private final static String x509CertificatePem = "-----BEGIN CERTIFICATE-----\n" +
            "MIICGDCCAb+gAwIBAgIQHWBLQRSL/SxAckSUBCAceDAKBggqhkjOPQQDAjBzMQsw\n" +
            "CQYDVQQGEwJVUzETMBEGA1UECBMKQ2FsaWZvcm5pYTEWMBQGA1UEBxMNU2FuIEZy\n" +
            "YW5jaXNjbzEZMBcGA1UEChMQb3JnMS5leGFtcGxlLmNvbTEcMBoGA1UEAxMTY2Eu\n" +
            "b3JnMS5leGFtcGxlLmNvbTAeFw0xOTEyMTAxMzA1MDBaFw0yOTEyMDcxMzA1MDBa\n" +
            "MFsxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRYwFAYDVQQHEw1T\n" +
            "YW4gRnJhbmNpc2NvMR8wHQYDVQQDDBZVc2VyMUBvcmcxLmV4YW1wbGUuY29tMFkw\n" +
            "EwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEv4CMIDkoFaqG0LEj5e1rHdHS5fdaUcLo\n" +
            "5QPMEPp9xlF9coWfAZ8kVwzDhw+G4dDnZDNYrMoZK1XCpGMcsXsNcqNNMEswDgYD\n" +
            "VR0PAQH/BAQDAgeAMAwGA1UdEwEB/wQCMAAwKwYDVR0jBCQwIoAgwIX0Gf47FIot\n" +
            "fjItLkLWW7jHtTfOqKIDU6lUNl4rYwEwCgYIKoZIzj0EAwIDRwAwRAIgX7lWMVFu\n" +
            "O6R7m7rxRD/A8hmEVcogX6x1kt7NvWH0OfgCIHpKlOFXN50hrMirci4scErbc/ra\n" +
            "G8OCh+bs1rqfv9cM\n" +
            "-----END CERTIFICATE-----";
    private final static String pkcs8PrivateKeyPem = "-----BEGIN PRIVATE KEY-----\n" +
            "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg8yzkTu0ilOAwJZgj\n" +
            "fU/MO5V532NgyJEB7QW6KKsrTwGhRANCAAS/gIwgOSgVqobQsSPl7Wsd0dLl91pR\n" +
            "wujlA8wQ+n3GUX1yhZ8BnyRXDMOHD4bh0OdkM1isyhkrVcKkYxyxew1y\n" +
            "-----END PRIVATE KEY-----";

    private final String x509EdCertificatePem = "-----BEGIN CERTIFICATE-----\n" +
            "MIIB/DCCAaKgAwIBAgIRAPEpXrM4I5IE+DoWemB4QgowCgYIKoZIzj0EAwIwczEL\n" +
            "MAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWExFjAUBgNVBAcTDVNhbiBG\n" +
            "cmFuY2lzY28xGTAXBgNVBAoTEG9yZzMuZXhhbXBsZS5jb20xHDAaBgNVBAMTE2Nh\n" +
            "Lm9yZzMuZXhhbXBsZS5jb20wHhcNMjIxMTI0MTU0NzAwWhcNMzIxMTIxMTU0NzAw\n" +
            "WjBsMQswCQYDVQQGEwJVUzETMBEGA1UECBMKQ2FsaWZvcm5pYTEWMBQGA1UEBxMN\n" +
            "U2FuIEZyYW5jaXNjbzEPMA0GA1UECxMGY2xpZW50MR8wHQYDVQQDDBZVc2VyMUBv\n" +
            "cmczLmV4YW1wbGUuY29tMCowBQYDK2VwAyEA6fsMyYSIlNnurJIKiXzcmBWYmVha\n" +
            "KeFS0aiD1tgdzIyjTTBLMA4GA1UdDwEB/wQEAwIHgDAMBgNVHRMBAf8EAjAAMCsG\n" +
            "A1UdIwQkMCKAILdru8n5fu441eogpM1QkCnGx6a5AAbCN6g3F+QupVvCMAoGCCqG\n" +
            "SM49BAMCA0gAMEUCIQCj0ha3aAtb7C3PGrgZT0zVIIiwL0x5I1MlDGhvoYrGJAIg\n" +
            "aKwqPJ6h5O8ZWr/DQbRfTFE6yDFTJyWfayJLIXzHiRw=\n" +
            "-----END CERTIFICATE-----\n";
    private final String pkcs8EdPrivateKeyPem = "-----BEGIN PRIVATE KEY-----\n" + 
            "MC4CAQAwBQYDK2VwBCIEIIy/o6SuOCDSwfL4H3e6M9JxQSffp64BvnG1xb9Vgjyq\n" +
            "-----END PRIVATE KEY-----";

    @Test
    void certificate_read_error_throws_IOException() {
        String failMessage = "read failure";
        Reader reader = testUtils.newFailingReader(failMessage);

        assertThatThrownBy(() -> Identities.readX509Certificate(reader))
                .isInstanceOf(IOException.class)
                .hasMessage(failMessage);
    }

    @Test
    void bad_certificate_PEM_throws_CertificateException() {
        assertThatThrownBy(() -> Identities.readX509Certificate("Invalid PEM"))
                .isInstanceOf(CertificateException.class);
    }

    @Test
    void bad_certificate_throws_CertificateException() {
        String pem = "-----BEGIN CERTIFICATE-----\n" +
                Base64.getEncoder().encodeToString("Invalid certificate".getBytes(StandardCharsets.UTF_8)) + "\n" +
                "-----END CERTIFICATE-----";

        assertThatThrownBy(() -> Identities.readX509Certificate(pem))
                .isInstanceOf(CertificateException.class);
    }

    @Test
    void private_key_read_error_throws_IOException() {
        String failMessage = "read failure";
        Reader reader = testUtils.newFailingReader(failMessage);

        assertThatThrownBy(() -> Identities.readPrivateKey(reader))
                .isInstanceOf(IOException.class)
                .hasMessage(failMessage);
    }

    @Test
    void bad_private_key_PEM_throws_InvalidKeyException() {
        assertThatThrownBy(() -> Identities.readPrivateKey("Invalid PEM"))
                .isInstanceOf(InvalidKeyException.class);
    }

    @Test
    void bad_private_key_throws_InvalidKeyException() {
        String pem = "-----BEGIN PRIVATE KEY-----\n" +
                Base64.getEncoder().encodeToString("Invalid private key".getBytes(StandardCharsets.UTF_8)) + "\n" +
                "-----END PRIVATE KEY-----";

        assertThatThrownBy(() -> Identities.readPrivateKey(pem))
                .isInstanceOf(InvalidKeyException.class);
    }

    @Test
    void read_and_write_X509_certificate_PEM() throws CertificateException {
        Certificate certificate = Identities.readX509Certificate(x509CertificatePem);
        String result = Identities.toPemString(certificate);

        assertThat(result).isEqualToIgnoringNewLines(x509CertificatePem);
    }

    @Test
    void read_and_write_PKCS8_private_key_PEM() throws InvalidKeyException, IOException, NoSuchAlgorithmException, SignatureException, CertificateException {
        PrivateKey privateKey = Identities.readPrivateKey(pkcs8PrivateKeyPem);
        String result = Identities.toPemString(privateKey);

        PrivateKey fromIdentitiesPem = Identities.readPrivateKey(result);
        Signature signer = Signature.getInstance("NONEwithECDSA", BC_PROVIDER);
        signer.initSign(fromIdentitiesPem);
        signer.update("message".getBytes());
        byte[] sig = signer.sign();

        signer.initVerify(Identities.readX509Certificate(x509CertificatePem));
        signer.update("message".getBytes());

        assert(signer.verify(sig));
    }

    @Test
    void write_and_read_X509_certificate() throws CertificateException {
        Certificate expected = credentials.getCertificate();
        String pem = Identities.toPemString(expected);
        Certificate actual = Identities.readX509Certificate(pem);

        assertThat(actual).isEqualTo(expected);
    }

    @Test
    void write_and_read_private_key() throws InvalidKeyException {
        PrivateKey expected = credentials.getPrivateKey();
        String pem = Identities.toPemString(expected);
        PrivateKey actual = Identities.readPrivateKey(pem);

        assertThat(actual).isEqualTo(expected);
    }

    @Test
    void read_and_write_X509_ed25519_certificate_PEM() throws CertificateException {
        Certificate certificate = Identities.readX509Certificate(x509EdCertificatePem);
        String result = Identities.toPemString(certificate);

        assertThat(result).isEqualToIgnoringNewLines(x509EdCertificatePem);
    }

    @Test
    void read_and_write_PKCS8_ed2519_private_key_PEM() throws InvalidKeyException {
        PrivateKey privateKey = Identities.readPrivateKey(pkcs8EdPrivateKeyPem);
        String result = Identities.toPemString(privateKey);

        assertThat(result).isEqualToIgnoringNewLines(pkcs8EdPrivateKeyPem);
    }
}