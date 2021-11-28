package util

import (
	"fmt"
	"runtime"
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"
)

func DefaultPlatformName() string {
	os := runtime.GOOS
	switch os {
	case "darwin":
		// you probably didn't mean to select darwin as default!
		os = "linux"
	}
	arch := runtime.GOARCH
	var variant string
	switch arch {
	case "arm64":
		// images seem to mark as arm64/v8 now, ugh
		variant = "v8"
	case "arm":
		variant = "v7"
	}
	if variant != "" {
		variant = "/" + variant
	}
	return os + "/" + arch + variant
}

func ParsePlatform(platform string) (*v1.Platform, error) {
	p := &v1.Platform{}
	parts := strings.Split(platform, "/")

	if len(parts) < 2 {
		return nil, fmt.Errorf("failed to parse platform '%s': expected format os/arch[/variant]", platform)
	}
	if len(parts) > 3 {
		return nil, fmt.Errorf("failed to parse platform '%s': too many slashes", platform)
	}

	p.OS = parts[0]
	p.Architecture = parts[1]
	if len(parts) > 2 {
		p.Variant = parts[2]
	}

	return p, nil
}

func AppendAnnotation(a map[string]string, b map[string]string) map[string]string {
	for k, v := range b {
		a[k] = v
	}
	return a
}
