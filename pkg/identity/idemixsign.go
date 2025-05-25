package identity

import (
	"crypto"
	"fmt"

	math "github.com/IBM/mathlib"

	"github.com/IBM/idemix/bccsp/handlers"
	bridge "github.com/IBM/idemix/bccsp/schemes/dlog/bridge"
	idemix "github.com/IBM/idemix/bccsp/schemes/dlog/crypto"
	"github.com/IBM/idemix/bccsp/types"
	idemixmsp "github.com/IBM/idemix/idemixmsp"

	"crypto/rand"

	"github.com/golang/protobuf/proto"

	"github.com/IBM/idemix/bccsp/schemes/dlog/crypto/translator/amcl"
)

const (
	// DefaultIdemixCurve is the curve picked by Fabric-CA at default
	DefaultIdemixCurve = "amcl.Fp256bn"
)

// CurveIDs defines a collection of CurveIDs
type CurveIDs []math.CurveID

var (
	translators = [...]idemix.Translator{&amcl.Fp256bn{C: math.Curves[0]}, &amcl.Gurvy{C: math.Curves[1]}, &amcl.Fp256bnMiracl{C: math.Curves[2]}}
	// Curves lists all idemix curves that can be picked by Fabric-CA
	Curves = CurveIDs{math.FP256BN_AMCL, math.BN254, math.FP256BN_AMCL_MIRACL}

	// curvesByName maps the names of the curves as they appear in the configuration to their CurveID enum.
	curvesByName = map[string]math.CurveID{
		DefaultIdemixCurve:   math.FP256BN_AMCL,
		"gurvy.Bn254":        math.BN254,
		"amcl.Fp256Miraclbn": math.FP256BN_AMCL_MIRACL,
	}
)

func NewIdemixSign(mspConfig *idemixmsp.IdemixMSPConfig, idemixId *IdemixIdentity) (Sign, error) {
	idmx, idemixSigner := idemixImplForCurveId(mspConfig.CurveId)

	skBytes := mspConfig.Signer.Sk
	sk := idmx.Curve.NewZrFromBytes(skBytes)
	key := handlers.NewUserSecretKey(sk, true)

	var issuerPk idemix.IssuerPublicKey
	err := proto.Unmarshal(mspConfig.Ipk, &issuerPk)
	if err != nil {
		return nil, err
	}

	// TODO: enable idemix smart card
	signerOpts := newSignerOpts(&issuerPk, mspConfig)

	return func(digest []byte) ([]byte, error) {
		signerOpts.Nym = idemixId.GetNym()

		signature, err := idemixSigner.Sign(key, digest, signerOpts)
		return signature, err
	}, nil

}

// NewIdemixStaticCredSign signs a message using the same pseudonym
// TODO: johann i dont think this method is needed anymore
func NewIdemixStaticCredSign(
	nymSecretKey *handlers.NymSecretKey,
	mspConfig *idemixmsp.IdemixMSPConfig,
	idemixId *IdemixIdentity) (Sign, error) {

	idmx, idemixSigner := idemixImplForCurveId(mspConfig.CurveId)

	skBytes := mspConfig.Signer.Sk
	sk := idmx.Curve.NewZrFromBytes(skBytes)
	key := handlers.NewUserSecretKey(sk, true)

	var issuerPk idemix.IssuerPublicKey
	err := proto.Unmarshal(mspConfig.Ipk, &issuerPk)
	if err != nil {
		return nil, err
	}

	// TODO: enable idemix smart card
	signerOpts := newSignerOpts(&issuerPk, mspConfig)
	signerOpts.Nym = nymSecretKey

	publicKey, err := nymSecretKey.PublicKey()
	if err != nil {
		return nil, err
	}

	_ = publicKey

	// idemixId.SetNymPk(publicKey)

	return func(digest []byte) ([]byte, error) {
		signature, err := idemixSigner.Sign(key, digest, signerOpts)
		return signature, err
	}, nil

}

func idemixImplForCurveId(curveId string) (*idemix.Idemix, *handlers.Signer) {
	curveIdInt, ok := curvesByName[curveId]
	if !ok {
		panic(fmt.Sprintf("curveId %s not found", curveId))
	}

	// TODO: check curveid
	curve := math.Curves[curveIdInt]
	translator := translators[curveIdInt]

	idmx := &idemix.Idemix{
		Curve:      curve,
		Translator: translator,
	}

	idemixSigner := &handlers.Signer{
		SignatureScheme: &bridge.SignatureScheme{
			Idemix: idmx, Translator: idmx.Translator,
		},
	}
	return idmx, idemixSigner
}

func newSignerOpts(issuerPk *idemix.IssuerPublicKey, mspConfig *idemixmsp.IdemixMSPConfig) *types.IdemixSignerOpts {
	signerOpts := &types.IdemixSignerOpts{
		Nym:        nil,
		Credential: mspConfig.Signer.Cred,
		IssuerPK: handlers.NewIssuerPublicKey(
			&bridge.IssuerPublicKey{
				PK: issuerPk,
			},
		),
		Attributes: []types.IdemixAttribute{
			{Type: types.IdemixBytesAttribute},
			{Type: types.IdemixIntAttribute},
			// {Type: types.IdemixBytesAttribute},
			{Type: types.IdemixHiddenAttribute},
			{Type: types.IdemixHiddenAttribute},
		},
		CRI: mspConfig.Signer.GetCredentialRevocationInformation(),
		H:   crypto.SHA256,
	}
	return signerOpts
}

// makeNewNymSecretKey creates a new pseudonym for a new idemix signature
func makeNewNymSecretKey(sk *math.Zr,
	issuerPk *idemix.IssuerPublicKey,
	idmx *idemix.Idemix,
	translator idemix.Translator,
) (*handlers.NymSecretKey, error) {
	ecp, big, err := idmx.MakeNym(sk, issuerPk, rand.Reader, translator)
	if err != nil {
		return nil, err
	}

	nymSecretKey, err := handlers.NewNymSecretKey(big, ecp, translator, true)
	nymSecretKey.PublicKey()
	if err != nil {
		return nil, err
	}
	return nymSecretKey, nil
}

func genCredentialProof(mspConfig *idemixmsp.IdemixMSPConfig) ([]byte, error) {
	idmx, idemixSigner := idemixImplForCurveId(mspConfig.CurveId)

	skBytes := mspConfig.Signer.Sk
	sk := idmx.Curve.NewZrFromBytes(skBytes)
	key := handlers.NewUserSecretKey(sk, true)

	var issuerPk idemix.IssuerPublicKey
	err := proto.Unmarshal(mspConfig.Ipk, &issuerPk)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal issuer public key: %v", err)
	}

	// TODO: enable idemix smart card
	signerOpts := newSignerOpts(&issuerPk, mspConfig)
	signerOpts.Nym, err = makeNewNymSecretKey(sk, &issuerPk, idmx, idmx.Translator)
	if err != nil {
		return nil, fmt.Errorf("failed to create nym secret key: %v", err)
	}

	signature, err := idemixSigner.Sign(key, nil, signerOpts)

	return signature, err
}
