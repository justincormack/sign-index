package signing

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"
)

// this is a set of constants for names of annotations

// SignatureVersion is the annotation label for signature version
const SignatureVersion = "org.notaryproject.signature.version"

// Version is the signature specification version
const Version = "0.2"

// Descriptor is the annotation where the signed descriptor is stored
const Descriptor = "org.notaryproject.signature.descriptor"

// SignatureType is the annotation for the signature type
const SignatureType = "org.notaryproject.signature.type"

// SignatureData is the actual signature
const SignatureData = "org.notaryproject.signature.data"

// SignatureIdentity is a hint for the identity of the signer
const SignatureIdentity = "org.notaryproject.signature.identity"

// ssh namespace. We could just use "container" I guess too.
const namespace = "org.notaryproject.sign"

// annotation prefix for unverified annotations
const prefix = "org.notaryproject.signature."

// Sign signs a given descriptor, returning annotations to add
func Sign(tp string, d v1.Descriptor, keyFile string, identity string) (map[string]string, error) {

	// we are going to sign the descriptor as JSON bytes
	data, err := json.Marshal(d)
	if err != nil {
		return nil, err
	}

	switch tp {
	case "ssh":
		return SignSSH(data, keyFile, identity)
	default:
		return nil, fmt.Errorf("Unsupported signature type: %s", tp)
	}
}

// SignSSH signs using ssh signature, shells out to ssh-keygen.
func SignSSH(data []byte, keyFile string, identity string) (map[string]string, error) {
	if keyFile == "" {
		return nil, fmt.Errorf("Must specify keyfile for signing key")
	}

	// annotations for the signature
	a := make(map[string]string)

	// version
	a[SignatureVersion] = Version

	// identity
	a[SignatureIdentity] = identity

	// we store the signed descriptor as base64 in an annotation
	a[Descriptor] = base64.StdEncoding.EncodeToString(data)

	// while there are libraries for using ssh in Go, they don't necessarily
	// work with all configurations, such as hardware keys, so lets exec
	cmd := exec.Command("ssh-keygen", "-Y", "sign", "-f", keyFile, "-n", namespace)
	cmd.Stdin = bytes.NewReader(data)
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		return nil, fmt.Errorf("Error calling ssh-keygen: %s")
	}
	signature := out.Bytes()
	a[SignatureType] = "ssh"
	a[SignatureData] = base64.StdEncoding.EncodeToString(signature)

	return a, nil
}

// Verify will check a signature in the provided descriptor. Pass a file of allowed signers.
func Verify(verifyDesc v1.Descriptor, allowed string) error {
	a := verifyDesc.Annotations
	version := a[SignatureVersion]
	if version == "" {
		return fmt.Errorf("Cannot find valid signature for digest %s (missing version)", verifyDesc.Digest.String())
	}
	if version != Version {
		return fmt.Errorf("Signature version mismatch, expecting %s got %s\n", Version, version)
	}

	tp := a[SignatureType]
	switch tp {
	case "":
		return fmt.Errorf("Cannot find valid signature for digest %s (missing type)", verifyDesc.Digest.String())
	case "ssh":
		return VerifySSH(verifyDesc, allowed)
	default:
		return fmt.Errorf("Unknown signature type: %s", tp)
	}

}

func VerifySSH(verifyDesc v1.Descriptor, allowed string) error {
	a := verifyDesc.Annotations
	signedDescStr := a[Descriptor]
	if signedDescStr == "" {
		return fmt.Errorf("Cannot find valid signed descriptor")
	}
	signedDescBytes, err := base64.StdEncoding.DecodeString(signedDescStr)
	if err != nil {
		return err
	}
	var signedDesc v1.Descriptor
	err = json.Unmarshal(signedDescBytes, &signedDesc)
	if err != nil {
		return err
	}
	signatureStr := a[SignatureData]
	signature, err := base64.StdEncoding.DecodeString(signatureStr)
	if err != nil {
		return err
	}
	identity := a[SignatureIdentity]

	// save signature to a temporary file
	sigFile, err := ioutil.TempFile("", "sig")
	if err != nil {
		sigFile.Close()
		return err
	}
	_, err = io.Copy(sigFile, bytes.NewBuffer(signature))
	if err != nil {
		sigFile.Close()
		os.Remove(sigFile.Name())
		return err
	}
	sigFile.Close()
	defer os.Remove(sigFile.Name())

	cmd := exec.Command("ssh-keygen", "-Y", "verify", "-f", allowed, "-I", identity, "-n", namespace, "-s", sigFile.Name())
	cmd.Stdin = bytes.NewReader(signedDescBytes)
	var out bytes.Buffer
	cmd.Stdout = &out
	err = cmd.Run()
	if err != nil {
		var eerr *exec.Error
		if errors.As(err, &eerr) {
			return fmt.Errorf("Error calling ssh-keygen: %s", err)
		}
		var exerr *exec.ExitError
		if errors.As(err, &exerr) {
			return fmt.Errorf("Signature validation failed: %s", out.String())
		}
		return err
	}

	// note we need to reverify descriptor after signature check!
	// everything in the descriptor should be in the signed descriptor
	// it is ok if there are more fields in the signed descriptor, eg expiry
	// perhaps we should sort arrays before comparing?
	// Alternatively, just use the signed descriptor not the original one, for
	// example we can reconstruct a new index from the signed descriptors, rather
	// than checking they match.
	if signedDesc.MediaType != verifyDesc.MediaType {
		return fmt.Errorf("Mismatch in media type in descriptor: signed %s verify %s", signedDesc.MediaType, verifyDesc.MediaType)
	}
	if signedDesc.Size != verifyDesc.Size {
		return fmt.Errorf("Mismatch in size in descriptor: signed %d verify %d", signedDesc.Size, verifyDesc.Size)
	}
	if signedDesc.Digest.Algorithm != verifyDesc.Digest.Algorithm {
		return fmt.Errorf("Mismatch in hash type in descriptor: signed %s verify %s", signedDesc.Digest.Algorithm, verifyDesc.Digest.Algorithm)
	}
	if signedDesc.Digest.Hex != verifyDesc.Digest.Hex {
		return fmt.Errorf("Mismatch in hash in descriptor: signed %s verify %s", signedDesc.Digest.Hex, verifyDesc.Digest.Hex)
	}
	// we do not check Data in descriptor as any use of it will check it against hash
	if len(signedDesc.URLs) != len(verifyDesc.URLs) {
		return fmt.Errorf("Mismatch in number of URLs in descriptor: signed %d verify %d", len(signedDesc.URLs), len(verifyDesc.URLs))
	}
	for i, u := range verifyDesc.URLs {
		if u != signedDesc.URLs[i] {
			return fmt.Errorf("Mismatch in URL in descriptor: signed %s verify %s", signedDesc.URLs[i], u)
		}
	}
	if signedDesc.Platform.Architecture != verifyDesc.Platform.Architecture {
		return fmt.Errorf("Mismatch platform architecture in descriptor: signed %s verify %s", signedDesc.Platform.Architecture, verifyDesc.Platform.Architecture)
	}
	if signedDesc.Platform.OS != verifyDesc.Platform.OS {
		return fmt.Errorf("Mismatch platform OS in descriptor: signed %s verify %s", signedDesc.Platform.OS, verifyDesc.Platform.OS)
	}
	if signedDesc.Platform.OSVersion != verifyDesc.Platform.OSVersion {
		return fmt.Errorf("Mismatch platform OS version in descriptor: signed %s verify %s", signedDesc.Platform.OSVersion, verifyDesc.Platform.OSVersion)
	}
	if signedDesc.Platform.Variant != verifyDesc.Platform.Variant {
		return fmt.Errorf("Mismatch platform variant in descriptor: signed %s verify %s", signedDesc.Platform.Variant, verifyDesc.Platform.Variant)
	}
	if len(signedDesc.Platform.OSFeatures) != len(verifyDesc.Platform.OSFeatures) {
		return fmt.Errorf("Mismatch in number of OS features in descriptor: signed %d verify %d", len(signedDesc.Platform.OSFeatures), len(verifyDesc.Platform.OSFeatures))
	}
	for i, f := range verifyDesc.Platform.OSFeatures {
		if f != signedDesc.Platform.OSFeatures[i] {
			return fmt.Errorf("Mismatch in OS feature in descriptor: signed %s verify %s", signedDesc.Platform.OSFeatures[i], f)
		}
	}
	if len(signedDesc.Platform.Features) != len(verifyDesc.Platform.Features) {
		return fmt.Errorf("Mismatch in number of features in descriptor: signed %d verify %d", len(signedDesc.Platform.Features), len(verifyDesc.Platform.Features))
	}
	for i, f := range verifyDesc.Platform.Features {
		if f != signedDesc.Platform.Features[i] {
			return fmt.Errorf("Mismatch in feature in descriptor: signed %s verify %s", signedDesc.Platform.Features[i], f)
		}
	}
	for k, v := range verifyDesc.Annotations {
		// we did not sign the signature so skip these unverified fields
		if strings.HasPrefix(k, prefix) {
			continue
		}
		if signedDesc.Annotations[k] != v {
			return fmt.Errorf("Mismatch in annotation %s in descriptor: signed %s verify %s", k, signedDesc.Annotations[k], v)
		}
	}
	return nil
}
