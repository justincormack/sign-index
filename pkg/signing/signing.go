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

	v1 "github.com/google/go-containerregistry/pkg/v1"
)

// this is a set of constants for names of annotations
// they should become standardised and removed

// SignatureVersion is the annotation label for signature version
const SignatureVersion = "org.notaryproject.signature.version"

// Version is the signature specification version
const Version = "0.1"

// Descriptor is the annotation where the signed descriptor is stored
const Descriptor = "org.notaryproject.signature.descriptor"

// SignatureType is the annotation for the signature type
const SignatureType = "org.notaryproject.signature.type"

// SignatureData is the actual signature
const SignatureData = "org.notaryproject.signature.data"

// ssh namespace. We could just use "container" I guess too.
const namespace = "org.notaryproject.sign"

// Sign signs a given descriptor, returning annotations to add to the image index
func Sign(tp string, d v1.Descriptor, keyFile string) (map[string]string, error) {

	// we are going to sign the descriptor as JSON bytes
	data, err := json.Marshal(d)
	if err != nil {
		return nil, err
	}

	// need to pass the digest of the descriptor for looking up in annotations
	// TODO add signer to suffix?
	suffix := "." + d.Digest.String()

	switch tp {
	case "ssh":
		return SignSSH(data, suffix, keyFile)
	default:
		return nil, fmt.Errorf("Unsupported signature type: %s", tp)
	}
}

// SignSSH signs using ssh signature, shells out to ssh-keygen.
func SignSSH(data []byte, suffix string, keyFile string) (map[string]string, error) {
	if keyFile == "" {
		return nil, fmt.Errorf("Must specify keyfile for signing key")
	}

	// annotations for the signature
	a := make(map[string]string)

	// version
	a[SignatureVersion+suffix] = Version

	// we store the signed descriptor as base64 in an annotation
	a[Descriptor+suffix] = base64.StdEncoding.EncodeToString(data)

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
	a[SignatureType+suffix] = "ssh"
	a[SignatureData+suffix] = base64.StdEncoding.EncodeToString(signature)

	return a, nil
}

// Verify will check a signature in the provided annotations against the provided descriptor
func Verify(a map[string]string, verifyDesc v1.Descriptor, signer string, allowed string) error {
	digest := verifyDesc.Digest.String()
	suffix := "." + digest

	version := a[SignatureVersion+suffix]
	if version == "" {
		return fmt.Errorf("Cannot find valid signature for digest %s (missing version)", digest)
	}
	if version != Version {
		return fmt.Errorf("Signature version mismatch, expecting %s got %s\n", Version, version)
	}

	tp := a[SignatureType+suffix]
	switch tp {
	case "":
		return fmt.Errorf("Cannot find valid signature for digest %s (missing type)", digest)
	case "ssh":
		return VerifySSH(a, suffix, verifyDesc, signer, allowed)
	default:
		return fmt.Errorf("Unknown signature type: %s", tp)
	}

}

func VerifySSH(a map[string]string, suffix string, verifyDesc v1.Descriptor, signer string, allowed string) error {
	signedDescStr := a[Descriptor+suffix]
	if signedDescStr == "" {
		return fmt.Errorf("Cannot find valid signed descriptor")
	}
	signedDesc, err := base64.StdEncoding.DecodeString(signedDescStr)
	if err != nil {
		return err
	}
	signatureStr := a[SignatureData+suffix]
	signature, err := base64.StdEncoding.DecodeString(signatureStr)
	if err != nil {
		return err
	}

	// save signature to a temporary file
	sigFile, err := ioutil.TempFile("", "sig")
	if err != nil {
		sigFile.Close()
		return err
	}
	_, err = io.Copy(sigFile, bytes.NewBuffer(signature))
	if err != nil {
		sigFile.Close()
		return err
	}
	sigFile.Close()
	defer os.Remove(sigFile.Name())

	cmd := exec.Command("ssh-keygen", "-Y", "verify", "-f", allowed, "-I", signer, "-n", namespace, "-s", sigFile.Name())
	cmd.Stdin = bytes.NewReader(signedDesc)
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

	return nil
}
