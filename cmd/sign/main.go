package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/justincormack/sign-index/pkg/signing"
	"github.com/justincormack/sign-index/pkg/util"
)

func main() {
	var tp string
	var keyFile string
	var putName string
	var identity string

	flag.StringVar(&tp, "type", "ssh", "Type of signing key (currently supports ssh).")
	flag.StringVar(&keyFile, "keyfile", "", "File containing key to sign with")
	flag.StringVar(&putName, "put", "", "New name to use when pushing rather than overwrite original manifest")
	// TODO we could parse this from the comment in the public key file
	flag.StringVar(&identity, "I", "", "Identity of signer")

	flag.Parse()

	if len(flag.Args()) != 1 {
		fmt.Println("usage: sign [flags] image")
		flag.PrintDefaults()
		os.Exit(1)
	}

	image := flag.Args()[0]

	ref, err := name.ParseReference(image)
	if err != nil {
		fmt.Println("Cannot parse image name %s: ", image, err)
		os.Exit(1)
	}

	if identity == "" {
		fmt.Println("Need to specify an identity")
		os.Exit(1)
	}

	if putName == "" {
		putName = image
	}
	putRef, err := name.ParseReference(putName)
	if err != nil {
		fmt.Println("Cannot parse image name %s: ", putName, err)
		os.Exit(1)
	}

	auth := remote.WithAuthFromKeychain(authn.DefaultKeychain)

	desc, err := remote.Get(ref, auth)
	if err != nil {
		fmt.Println("Cannot access remote index: ", err)
		os.Exit(1)
	}

	idx, err := desc.ImageIndex()
	if err != nil {
		fmt.Println("TODO: create an image index if you ask to sign a plain image: ", err)
		os.Exit(1)
	}

	im, err := idx.IndexManifest()
	if err != nil {
		fmt.Println("Cannot read manifest from image index: ", err)
		os.Exit(1)
	}

	// copy media type and annotations into new empty index
	signedIdx := mutate.IndexMediaType(empty.Index, im.MediaType)
	adds := []mutate.IndexAddendum{}
	for _, d := range im.Manifests {
		as, err := signing.Sign(tp, d, keyFile, identity)
		if err != nil {
			fmt.Println("Signing error: ", err)
			os.Exit(1)
		}
		var nd v1.Descriptor
		d.DeepCopyInto(&nd)
		if nd.Annotations == nil {
			nd.Annotations = make(map[string]string)
		}
		img, err := idx.Image(d.Digest)
		if err != nil {
			fmt.Println("Cannot get image: ", err)
			os.Exit(1)
		}
		nd.Annotations = util.AppendAnnotation(nd.Annotations, as)
		adds = append(adds, mutate.IndexAddendum{
			Add:        img,
			Descriptor: nd,
		})
	}
	signedIdx = mutate.AppendManifests(signedIdx, adds...)
	signedIdx = mutate.Annotations(signedIdx, im.Annotations).(v1.ImageIndex)

	ch := make(chan v1.Update, 100)
	go func() {
		_ = remote.WriteIndex(putRef, signedIdx, auth, remote.WithProgress(ch))
	}()
	for update := range ch {
		switch {
		case update.Error != nil && errors.Is(update.Error, io.EOF):
			fmt.Fprintf(os.Stderr, "\n")
			break
		case update.Error != nil:
			fmt.Printf("error writing tarball: %v\n", update.Error)
			os.Exit(1)
		default:
			fmt.Fprintf(os.Stderr, ".")
		}
	}

}
