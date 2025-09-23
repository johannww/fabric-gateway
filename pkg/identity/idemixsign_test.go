package identity

import (
	"os"
	"path"
	"testing"

	"github.com/IBM/idemix/bccsp/handlers"
	bridge "github.com/IBM/idemix/bccsp/schemes/dlog/bridge"
	idemix "github.com/IBM/idemix/bccsp/schemes/dlog/crypto"
	"github.com/IBM/idemix/bccsp/types"
	"github.com/hyperledger/fabric-protos-go-apiv2/msp"

	math "github.com/IBM/mathlib"
	"github.com/golang/protobuf/proto"
	"github.com/stretchr/testify/require"
)

const (
	dataDir          = "testdata"
	IssuerPkPath     = "IssuerPublicKey"
	RevocationPkPath = "IssuerRevocationPublicKey"
	SignerConfigPath = "user/SignerConfig"
)

func TestIdentityValidity(t *testing.T) {
	issuerPkBytes, err := os.ReadFile(path.Join(dataDir, IssuerPkPath))
	require.NoError(t, err, "failed to read issuer public key: %v", err)
	revocationPkPemBytes, err := os.ReadFile(path.Join(dataDir, RevocationPkPath))
	require.NoError(t, err, "failed to read revocation public key: %v", err)
	signerConfBytes, err := os.ReadFile(path.Join(dataDir, SignerConfigPath))
	require.NoError(t, err, "failed to read signer config: %v", err)

	issuerPk, err := IssuerPublicKeyFromBytes(issuerPkBytes)
	require.NoError(t, err, "failed to unmarshal issuer public key: %v", err)

	revocationPkImporter := &handlers.RevocationPublicKeyImporter{}
	revocationPk, err := revocationPkImporter.KeyImport(revocationPkPemBytes, nil)
	require.NoError(t, err, "failed to import revocation public key: %v", err)

	mspConfig := IdemixMspConfigFromBytes("mockMSP", issuerPkBytes, revocationPkPemBytes)

	signerConf, err := IdemixSignerConfigFromBytes(mspConfig, signerConfBytes)
	require.NoError(t, err, "failed to unmarshal signer config: %v", err)

	curveIdInt := curvesByName[mspConfig.CurveId]
	curve := math.Curves[curveIdInt]
	translator := translators[curveIdInt]
	idmx := &idemix.Idemix{
		Curve:      curve,
		Translator: translator,
	}

	idemixId, err := NewIdemixIdentity("mockMSP", signerConf, mspConfig)
	require.NoError(t, err, "failed to create idemix identity: %v", err)
	err = idemixId.NewPseudonym()
	require.NoError(t, err, "failed to create pseudonym: %v", err)

	verifier := &handlers.Verifier{
		SignatureScheme: &bridge.SignatureScheme{
			Idemix: idmx, Translator: translator,
		},
	}

	var cred idemix.Credential
	err = proto.Unmarshal(mspConfig.Signer.Cred, &cred)
	require.NoError(t, err, "failed to unmarshal credential: %v", err)

	serializedId := idemixId.idmxSerializedIdentity

	var mspRole msp.MSPRole
	proto.Unmarshal(serializedId.Role, &mspRole)

	var ou msp.OrganizationUnit
	err = proto.Unmarshal(serializedId.Ou, &ou)

	signerOpts := &types.IdemixSignerOpts{
		IssuerPK: handlers.NewIssuerPublicKey(
			&bridge.IssuerPublicKey{
				PK: issuerPk,
			},
		),
		RevocationPublicKey: revocationPk,
		Attributes: []types.IdemixAttribute{
			// {Type: types.IdemixBytesAttribute, Value: []byte(signerConf.OrganizationalUnitIdentifier)},
			// {Type: types.IdemixIntAttribute, Value: int(signerConf.Role)},
			{Type: types.IdemixBytesAttribute, Value: []byte(ou.OrganizationalUnitIdentifier)},
			{Type: types.IdemixIntAttribute, Value: int(getIdemixRoleFromMSPRoleType(mspRole.Role))},
			// {Type: types.IdemixBytesAttribute, Value: []byte(signerConf.EnrollmentId)},
			{Type: types.IdemixHiddenAttribute},
			{Type: types.IdemixHiddenAttribute},
		},
		RhIndex:  3,
		EidIndex: 2,
		Epoch:    0,
	}

	verify, err := verifier.Verify(signerOpts.IssuerPK, serializedId.Proof, nil, signerOpts)
	require.NoError(t, err, "failed to verify association proof: %v", err)
	require.True(t, verify, "identity association profo verification failed")

}

func TestNymIdemixSign(t *testing.T) {
	issuerPkBytes, err := os.ReadFile(path.Join(dataDir, IssuerPkPath))
	require.NoError(t, err, "failed to read issuer public key: %v", err)
	revocationPkPemBytes, err := os.ReadFile(path.Join(dataDir, RevocationPkPath))
	require.NoError(t, err, "failed to read revocation public key: %v", err)
	signerConfBytes, err := os.ReadFile(path.Join(dataDir, SignerConfigPath))
	require.NoError(t, err, "failed to read signer config: %v", err)

	issuerPk, err := IssuerPublicKeyFromBytes(issuerPkBytes)
	require.NoError(t, err, "failed to unmarshal issuer public key: %v", err)

	mspConfig := IdemixMspConfigFromBytes("mockMSP", issuerPkBytes, revocationPkPemBytes)

	signerConf, err := IdemixSignerConfigFromBytes(mspConfig, signerConfBytes)
	require.NoError(t, err, "failed to unmarshal signer config: %v", err)

	curveIdInt := curvesByName[mspConfig.CurveId]
	curve := math.Curves[curveIdInt]
	translator := translators[curveIdInt]
	idmx := &idemix.Idemix{
		Curve:      curve,
		Translator: translator,
	}

	idemixId, err := NewIdemixIdentity("mockMSP", signerConf, mspConfig)
	require.NoError(t, err, "failed to create idemix identity: %v", err)
	err = idemixId.NewPseudonym()
	require.NoError(t, err, "failed to create pseudonym: %v", err)

	// signFunc, err := NewIdemixStaticNymSign(sk, issuerKey.GetIpk(), nymSecretKey)
	signFunc, err := NewIdemixSign(mspConfig, idemixId)
	require.NoError(t, err, "failed to create signer: %v", err)

	signature, err := signFunc([]byte("a msg"))
	require.NoError(t, err, "failed to sign: %v", err)

	verifier := &handlers.NymVerifier{
		NymSignatureScheme: &bridge.NymSignatureScheme{
			Idemix: idmx, Translator: translator,
		},
	}

	var cred idemix.Credential
	err = proto.Unmarshal(mspConfig.Signer.Cred, &cred)
	require.NoError(t, err, "failed to unmarshal credential: %v", err)

	// nymPk, err := nymSecretKey.PublicKey()
	nymPk, err := idemixId.GetNymPublicKey()
	require.NoError(t, err, "failed to get public key: %v", err)

	signerOpts := &types.IdemixNymSignerOpts{
		Nym: nymPk,
		IssuerPK: handlers.NewIssuerPublicKey(
			&bridge.IssuerPublicKey{
				PK: issuerPk,
			},
		),
	}

	verify, err := verifier.Verify(nymPk, signature, []byte("a msg"), signerOpts)
	require.NoError(t, err, "failed to verify: %v", err)
	require.True(t, verify, "signature verification failed")

}
