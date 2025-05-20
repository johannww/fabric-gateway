package identity

import (
	"crypto"
	"os"
	"path"
	"testing"

	"github.com/IBM/idemix/bccsp/handlers"
	bridge "github.com/IBM/idemix/bccsp/schemes/dlog/bridge"
	idemix "github.com/IBM/idemix/bccsp/schemes/dlog/crypto"
	"github.com/IBM/idemix/bccsp/types"

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

func TestIdemixSign(t *testing.T) {
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

	// signFunc, err := NewIdemixStaticNymSign(sk, issuerKey.GetIpk(), nymSecretKey)
	signFunc, err := NewIdemixSign(mspConfig, idemixId)
	require.NoError(t, err, "failed to create signer: %v", err)

	signature, err := signFunc([]byte("a digest"))
	require.NoError(t, err, "failed to sign: %v", err)

	verifier := &handlers.Verifier{
		SignatureScheme: &bridge.SignatureScheme{
			Idemix: idmx, Translator: translator,
		},
	}

	var cred idemix.Credential
	err = proto.Unmarshal(mspConfig.Signer.Cred, &cred)
	require.NoError(t, err, "failed to unmarshal credential: %v", err)

	// nymPk, err := nymSecretKey.PublicKey()
	nymPk := idemixId.GetNymPublicKey()
	require.NoError(t, err, "failed to get public key: %v", err)

	signerOpts := &types.IdemixSignerOpts{
		Nym: nymPk,
		IssuerPK: handlers.NewIssuerPublicKey(
			&bridge.IssuerPublicKey{
				PK: issuerPk,
			},
		),
		Attributes: []types.IdemixAttribute{
			{Type: types.IdemixBytesAttribute, Value: []byte(signerConf.OrganizationalUnitIdentifier)},
			{Type: types.IdemixIntAttribute, Value: int(signerConf.Role)},
			// {Type: types.IdemixBytesAttribute, Value: []byte(signerConf.EnrollmentId)},
			{Type: types.IdemixHiddenAttribute},
			{Type: types.IdemixHiddenAttribute},
		},
		H: crypto.SHA256,
	}

	verify, err := verifier.Verify(signerOpts.IssuerPK, signature, []byte("a digest"), signerOpts)
	// verify, err := verifier.Verify(nymPk, signature, []byte("a digest"), signerOpts)
	require.NoError(t, err, "failed to verify: %v", err)
	require.True(t, verify, "signature verification failed")

}

func TestIdemixSignWithStaticNym(t *testing.T) {
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

	skBytes := mspConfig.Signer.Sk
	sk := curve.NewZrFromBytes(skBytes)

	idemixId, err := NewIdemixIdentity("mockMSP", signerConf, mspConfig)
	require.NoError(t, err, "failed to create idemix identity: %v", err)

	nymSecretKey, err := makeNewNymSecretKey(sk, issuerPk, idmx, translator)
	require.NoError(t, err, "failed to create nym secret key: %v", err)

	// signFunc, err := NewIdemixStaticNymSign(sk, issuerKey.GetIpk(), nymSecretKey)
	signFunc, err := NewIdemixStaticCredSign(nymSecretKey, mspConfig, idemixId)
	require.NoError(t, err, "failed to create signer: %v", err)

	signature, err := signFunc([]byte("a digest"))
	require.NoError(t, err, "failed to sign: %v", err)

	verifier := &handlers.Verifier{
		SignatureScheme: &bridge.SignatureScheme{
			Idemix: idmx, Translator: translator,
		},
	}

	var cred idemix.Credential
	err = proto.Unmarshal(mspConfig.Signer.Cred, &cred)
	require.NoError(t, err, "failed to unmarshal credential: %v", err)

	// nymPk, err := nymSecretKey.PublicKey()
	nymPk := idemixId.GetNymPublicKey()
	require.NoError(t, err, "failed to get public key: %v", err)

	signerOpts := &types.IdemixSignerOpts{
		Nym: nymPk,
		IssuerPK: handlers.NewIssuerPublicKey(
			&bridge.IssuerPublicKey{
				PK: issuerPk,
			},
		),
		Attributes: []types.IdemixAttribute{
			{Type: types.IdemixBytesAttribute, Value: []byte(signerConf.OrganizationalUnitIdentifier)},
			{Type: types.IdemixIntAttribute, Value: int(signerConf.Role)},
			// {Type: types.IdemixBytesAttribute, Value: []byte(signerConf.EnrollmentId)},
			{Type: types.IdemixHiddenAttribute},
			{Type: types.IdemixHiddenAttribute},
		},
		H: crypto.SHA256,
	}

	verify, err := verifier.Verify(signerOpts.IssuerPK, signature, []byte("a digest"), signerOpts)
	// verify, err := verifier.Verify(nymPk, signature, []byte("a digest"), signerOpts)
	require.NoError(t, err, "failed to verify: %v", err)
	require.True(t, verify, "signature verification failed")

}
