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
	idmxSerializedIdentity *idemixmsp.SerializedIdemixIdentity
	nymPk                  types.Key
}

func (id *IdemixIdentity) MspID() string {
	return id.mspID
}

func (id *IdemixIdentity) Credentials() []byte {
	credentials, _ := proto.Marshal(id.idmxSerializedIdentity)
	return credentials
}

// NewIdemixIdentity creates a new Identity from an Idemix credential.
func NewIdemixIdentity(mspID string,
	signerConf *idemixmsp.IdemixMSPSignerConfig,
	mspConfig *idemixmsp.IdemixMSPConfig) (*IdemixIdentity, error) {
	identity := &IdemixIdentity{
		mspID: mspID,
		// credentials: credential,
	}

	identity.idmxSerializedIdentity = &idemixmsp.SerializedIdemixIdentity{}

	err := identity.CalculateProof(signerConf, mspConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to calculate identity's proof: %v", err)
	}

	var issuerPk idemix.IssuerPublicKey
	err = proto.Unmarshal(mspConfig.Ipk, &issuerPk)

	ou := &fabricmsp.OrganizationUnit{
		MspIdentifier:                mspID,
		OrganizationalUnitIdentifier: signerConf.OrganizationalUnitIdentifier,
		CertifiersIdentifier:         issuerPk.Hash,
	}
	ouBytes, err := proto.Marshal(ou)

	role := &fabricmsp.MSPRole{
		MspIdentifier: mspID,
		Role:          fabricmsp.MSPRole_MSPRoleType(signerConf.Role),
	}
	roleBytes, err := proto.Marshal(role)

	identity.idmxSerializedIdentity.Ou = ouBytes
	identity.idmxSerializedIdentity.Role = roleBytes

	return identity, nil
}

func (id *IdemixIdentity) CalculateProof(signerConf *idemixmsp.IdemixMSPSignerConfig, mspConfig *idemixmsp.IdemixMSPConfig) error {
	// Create the cryptographic evidence that this identity is valid
	// NewIdemixStaticCredSign()

	mspConfig.Signer = signerConf
	mspConfig.CurveId = signerConf.CurveId

	proof, err := genCredentialProof(mspConfig)
	if err != nil {
		return fmt.Errorf("failed to generate credential proof: %v", err)
	}
	id.idmxSerializedIdentity.Proof = proof
	return nil
	// proof, err := msp.csp.Sign(
	// 	UserKey,
	// 	nil,
	// 	&bccsp.IdemixSignerOpts{
	// 		Credential: conf.Signer.Cred,
	// 		Nym:        NymKey,
	// 		IssuerPK:   IssuerPublicKey,
	// 		Attributes: []bccsp.IdemixAttribute{
	// 			{Type: bccsp.IdemixBytesAttribute},
	// 			{Type: bccsp.IdemixIntAttribute},
	// 			{Type: bccsp.IdemixHiddenAttribute},
	// 			{Type: bccsp.IdemixHiddenAttribute},
	// 		},
	// 		RhIndex:  rhIndex,
	// 		EidIndex: eidIndex,
	// 		CRI:      conf.Signer.CredentialRevocationInformation,
	// 	},
	// )
}

func (id *IdemixIdentity) SetNymPk(nymPublicKey types.Key) {
	raw, _ := nymPublicKey.Bytes()
	id.idmxSerializedIdentity.NymX = raw[:len(raw)/2]
	id.idmxSerializedIdentity.NymY = raw[len(raw)/2:]
	id.nymPk = nymPublicKey
}

func (id *IdemixIdentity) GetNymPublicKey() types.Key {
	return id.nymPk
}
