package identity

import (
	"encoding/json"
	"fmt"

	idemix "github.com/IBM/idemix/bccsp/schemes/dlog/crypto"
	idemixmsp "github.com/IBM/idemix/idemixmsp"
	"github.com/golang/protobuf/proto"
)

func IssuerPublicKeyFromBytes(issuerPkBytes []byte) (*idemix.IssuerPublicKey, error) {
	var issuerPk idemix.IssuerPublicKey
	err := proto.Unmarshal(issuerPkBytes, &issuerPk)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal issuer public key: %v", err)
	}
	return &issuerPk, nil
}

func IdemixMspConfigFromBytes(mspID string, issuerPkBytes, revocationPkPemBytes []byte) *idemixmsp.IdemixMSPConfig {
	mspConfig := &idemixmsp.IdemixMSPConfig{
		Name:         mspID,
		Ipk:          issuerPkBytes,
		RevocationPk: revocationPkPemBytes,
	}
	return mspConfig
}

func IdemixSignerConfigFromBytes(mspConfig *idemixmsp.IdemixMSPConfig, signerConfBytes []byte) (*idemixmsp.IdemixMSPSignerConfig, error) {
	var signerConf idemixmsp.IdemixMSPSignerConfig
	err := json.Unmarshal(signerConfBytes, &signerConf)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal signer config: %v", err)
	}

	mspConfig.Signer = &signerConf
	mspConfig.CurveId = mspConfig.Signer.CurveId

	return &signerConf, nil
}
