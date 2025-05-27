// Copyright IBM Corp. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package identity defines a client identity and signing implementation used to interact with a Fabric network.
//
// This package provides utilities to aid creation of client identities and accompanying signing implementations from
// various types of credentials.
package identity

import (
	"crypto/x509"
	"fmt"

	idemix "github.com/IBM/idemix/bccsp/schemes/dlog/crypto"
	"github.com/IBM/idemix/bccsp/types"
	idemixmsp "github.com/IBM/idemix/idemixmsp"
	fabricmsp "github.com/hyperledger/fabric-protos-go-apiv2/msp"

	"github.com/golang/protobuf/proto"
)

// Identity represents a client identity used to interact with a Fabric network.
type Identity interface {
	MspID() string       // ID of the Membership Service Provider to which this identity belongs.
	Credentials() []byte // Implementation-specific credentials.
}

// X509Identity represents a client identity backed by an X.509 certificate.
type X509Identity struct {
	mspID       string
	certificate []byte
}

// MspID returns the ID of the Membership Service Provider to which this identity belongs.
func (id *X509Identity) MspID() string {
	return id.mspID
}

// Credentials as an X.509 certificate in PEM encoded ASN.1 DER format.
func (id *X509Identity) Credentials() []byte {
	return id.certificate
}

// NewX509Identity creates a new Identity from an X.509 certificate.
func NewX509Identity(mspID string, certificate *x509.Certificate) (*X509Identity, error) {
	certificatePEM, err := CertificateToPEM(certificate)
	if err != nil {
		return nil, err
	}

	identity := &X509Identity{
		mspID:       mspID,
		certificate: certificatePEM,
	}
	return identity, nil
}

// X509Identity represents a client identity backed by an X.509 certificate.
type IdemixIdentity struct {
	mspID                  string
	mspConfig              *idemixmsp.IdemixMSPConfig
	idmxSerializedIdentity *idemixmsp.SerializedIdemixIdentity
	nym                    types.Key
}

func (id *IdemixIdentity) MspID() string {
	return id.mspID
}

func (id *IdemixIdentity) Credentials() []byte {
	credentials, err := proto.Marshal(id.idmxSerializedIdentity)
	if err != nil {
		panic(fmt.Errorf("failed to marshal Idemix identity: %v", err))
	}
	return credentials
}

// NewIdemixIdentity creates a new Identity from an Idemix credential.
func NewIdemixIdentity(mspID string,
	signerConf *idemixmsp.IdemixMSPSignerConfig,
	mspConfig *idemixmsp.IdemixMSPConfig) (*IdemixIdentity, error) {
	identity := &IdemixIdentity{
		mspID: mspID,
		// credentials: credential,
		mspConfig: mspConfig,
	}

	identity.idmxSerializedIdentity = &idemixmsp.SerializedIdemixIdentity{}

	identity.mspConfig.Signer = signerConf
	identity.mspConfig.CurveId = signerConf.CurveId

	var issuerPk idemix.IssuerPublicKey
	err := proto.Unmarshal(mspConfig.Ipk, &issuerPk)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal issuer public key: %v", err)
	}

	ou := &fabricmsp.OrganizationUnit{
		MspIdentifier:                mspID,
		OrganizationalUnitIdentifier: signerConf.OrganizationalUnitIdentifier,
		CertifiersIdentifier:         issuerPk.Hash,
	}
	ouBytes, err := proto.Marshal(ou)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal organizational unit: %v", err)
	}

	role := &fabricmsp.MSPRole{
		MspIdentifier: mspID,
		// TODO: This works, but is semantically wrong.
		// signerConf.Role is actually an idemix.Role:
		// (https://github.com/IBM/idemix/tree/main/idemix_roles.go#L13).
		// This is because the Idemix MSP tests for the ADMIN idemix.Role constant:
		// https://github.com/IBM/idemix/blob/832db18b94785ad2657d91da96dd6c3401af1616/idemixmsp.go#L205-L211
		// However, it should ideally follow the definitions of fabricmsp.MSPRole_MSPRoleType
		Role: getMemberOrAdminRole(signerConf.Role),
	}
	roleBytes, err := proto.Marshal(role)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal role: %v", err)
	}

	identity.idmxSerializedIdentity.Ou = ouBytes
	identity.idmxSerializedIdentity.Role = roleBytes

	return identity, nil
}

func (id *IdemixIdentity) NewPseudonym() error {
	idmx, _ := idemixImplForCurveId(id.mspConfig.CurveId)

	skBytes := id.mspConfig.Signer.Sk
	sk := idmx.Curve.NewZrFromBytes(skBytes)

	var issuerPk idemix.IssuerPublicKey
	err := proto.Unmarshal(id.mspConfig.Ipk, &issuerPk)
	if err != nil {
		return fmt.Errorf("failed to unmarshal issuer public key: %v", err)
	}

	id.nym, err = makeNewNymSecretKey(sk, &issuerPk, idmx, idmx.Translator)
	if err != nil {
		return fmt.Errorf("failed to create nym secret key: %v", err)
	}

	nymPk, _ := id.nym.PublicKey()
	raw, _ := nymPk.Bytes()
	id.idmxSerializedIdentity.NymX = raw[:len(raw)/2]
	id.idmxSerializedIdentity.NymY = raw[len(raw)/2:]

	err = id.CalculateProof()
	if err != nil {
		return fmt.Errorf("failed to calculate identity's proof: %v", err)
	}

	return nil
}

func (id *IdemixIdentity) GetNym() types.Key {
	return id.nym
}

func (id *IdemixIdentity) CalculateProof() error {
	proof, err := genCredentialProof(id.mspConfig, id.nym)
	if err != nil {
		return fmt.Errorf("failed to generate credential proof: %v", err)
	}
	id.idmxSerializedIdentity.Proof = proof
	return nil
}

func (id *IdemixIdentity) GetNymPublicKey() (types.Key, error) {
	return id.nym.PublicKey()
}

// Role : Represents a IdemixRole
type Role int32

const (
	MEMBER Role = 1
	ADMIN  Role = 2
	CLIENT Role = 4
	PEER   Role = 8
	// Next role values: 16, 32, 64 ...
)

func getMemberOrAdminRole(role int32) fabricmsp.MSPRole_MSPRoleType {
	if role == int32(ADMIN) {
		return fabricmsp.MSPRole_ADMIN
	}
	return fabricmsp.MSPRole_MEMBER
}
