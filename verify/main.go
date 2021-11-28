package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/justincormack/sign-index/pkg/signing"
	"github.com/justincormack/sign-index/pkg/util"
)

func main() {
	var platformName string
	var signer string
	var allowed string

	flag.StringVar(&platformName, "platform", util.DefaultPlatformName(), "Specifies the platform in the form os/arch[/variant] (e.g. linux/amd64).")
	// TODO read from metadata
	flag.StringVar(&signer, "signer", "", "Person expected to have signed the image")
	flag.StringVar(&allowed, "allowed", "", "File containing allowed keys (ssh format)")

	flag.Parse()

	platform, err := util.ParsePlatform(platformName)
	if err != nil {
		fmt.Println("Cannot parse platform: ", err)
		os.Exit(1)
	}

	if len(flag.Args()) != 1 {
		fmt.Println("Usage: sign [flags] image")
		flag.PrintDefaults()
		os.Exit(1)
	}
	image := flag.Args()[0]

	ref, err := name.ParseReference(image)
	if err != nil {
		fmt.Println("Cannot parse image name: ", err)
		os.Exit(1)
	}

	desc, err := remote.Get(ref, remote.WithAuthFromKeychain(authn.DefaultKeychain))
	if err != nil {
		fmt.Println("Cannot access remote index: ", err)
		os.Exit(1)
	}

	idx, err := desc.ImageIndex()
	if err != nil {
		fmt.Println("Reference is an image not an index, cannot be signed: ", err)
		os.Exit(1)
	}

	manifest, err := idx.IndexManifest()
	if err != nil {
		fmt.Println("Cannot get manifests from index: ", err)
		os.Exit(1)
	}

	// find the descriptor matching the architecture
	var match v1.Descriptor
	var found bool
	for _, d := range manifest.Manifests {
		if d.Platform != nil && platform.Equals(*d.Platform) {
			match = d
			found = true
			break
		}
	}
	if !found {
		fmt.Println("Cannot find matching platform to ", platform)
		os.Exit(1)
	}

	err = signing.Verify(manifest.Annotations, match, signer, allowed)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	fmt.Println("Validated signature")

	// pull in Docker
}
