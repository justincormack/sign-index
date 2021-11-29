# Prototype for inline signing of images in the image index.

When designing Notary v2 there was a strong consensus for having detached signatures. These are
signatures that are not embedded in the object being signed, so that the signature can be changed
without changing the content digest of the object.
However designing detached signatures had some issues. The clean design,
[adding generic references](https://github.com/oras-project/artifacts-spec) requires registries to implement
a new set of APIs, while the backward compatible design is to use some sort of tagging convention which leads
to additional tags to manage, and is confusing, as there are no tag namespaces in registries.

While being able to change and update signatures without changing the content is a useful feature for
some applications, many use cases do not need it. We can see this with git signing, that has the same
content addressing issues, inline signing is the norm and the designs for detached signatures do exist
but are still only being used for a few use cases. So this proposal for a design for inline signatures
is not designed to replace references but to provide a signing framework that can be used now in any
registry. It is not the design that you might want if you were designing the format from scratch, but
it seems a clean design on top of the standards that already exist.

Design constraints
- works on all registries without changes
- simple for clients to use
- clients that do not understand it will just ignore it without changes
- agnostic to signature format
- signs OCI descriptors
- avoid [embedding the signature](https://latacora.micro.blog/2019/07/24/how-not-to.html) in the object being signed
- no microfotmats or parsing in the implementation, so far as possible

The cleanest way to do this is to embed the signatures for images in the [image index](https://github.com/opencontainers/image-spec/blob/main/image-index.md).
All clients now support image indexes and it is not too much of an imposition to ask people who want
to sign images to create one. Most people seem to want images to be signed rather than the image index,
based on discussion in Notary v2. You will be able to sign an image index by pointing the image index with
the signatures at another image index that you sign; nested image indexes should be supported according to
the specification.

As an image index maybe cannot point at a blob (disputed) and having a signature be in image itself with
a config would involve lots of extra round trips, the simplest solution is to embed the signature entirely
in annotations. This is not the nicest design as we want to support many signatures, but seems to be a very
workable option.

The current prototype supports a single signature for each object in the manifest. This is not sufficient for
all use cases. TODO change to support multiple signatures per object, using suffixes for each signature.

In order to allow multiple signatrue without parsing the contents of annotations, which could lead to security
issues, we add the digest of the image being signed to each annotation name we use, for example

```
"org.notaryproject.signature.version.sha256:07bf76961aa4c7d4b6648087563dc15d5374e1ca10b16f1643d70c6d7d541ee6": "0.1"
```

This makes it easy to look up signature data for a particular manifest that you have the digest for, and this data
will compress well as the digest is used multiple times.

The signature is over a descriptor in JSON, which is included with the signature for verification. The code checks
that the descriptor in the image includes all the signed fields, so you can check before you pull that the media
type, size and annotations match the signed version, not just the digest. The signed descriptor can in principle
have additional fields as annotations, this should be used if you want to add extra validated data, such as is
used in Red Hat simple signing, which supports signature date and canonical image names. Common additional fields
should be standardised.

All the fields in the annotations outside the descriptor should be considered untrusted; generally these are inputs
to the verification process and the protocol will check they match the values at signing time.

Annotations in the prototype are
- `org.notaryproject.signature.version.<digest>` The version of the signing protocol, 0.1 so far. Maybe should
  remove this and have ``org.notaryproject.signature.v1. ...` instead.
- `org.notaryproject.signature.type.<digest` The type of the signature. I implemented `ssh` in this prototype for
  [ssh signatures](https://www.agwa.name/blog/post/ssh_signatures) as these are now supported in git and so are likely
  to be useful. Also everyone has an ssh key so this is easy to test out. They support embedded certificate chains
  and many signature formats, and have native Go support, although the prototype shells out. We could add a small
  number of options here, such as the JWT format we are discussing.
- `org.notaryproject.signature.identity.<digest>` is a hint for the identity of the signer. For SSH signatures this
  is the email address, which is used to look up signatures; it could be a public key identifier. If more identifiers
  are needed for finding keys we should add additional fields, but for many signing schemes a single one is enough.
- `org.notaryproject.signature.descriptor.<digest>` This is the signed descriptor, base64 encoded. As this is what
  is actually signed, all the data in it can be trusted. We verify that the descriptor for the image that is signed
  in the image index matches this descriptor.
- `org.notaryproject.signature.data.<digest>` This is the signature data, base64 encoded.

Other fields for untrusted data can be added, for example for a signed timestamp. Trusted fields need to be in the
descriptor or built into the signing protocol.

## How to use this prototype

This is a very simple prototype that will sign images with ssh keys to demonstrate the protocol. There are two
programs, `sign` and `verify`. For an introduction to SSH signing, see [this article](https://www.agwa.name/blog/post/ssh_signatures).

To sign an image you need to provide an ssh key file, eg your public key, and the identity to use (which we should be able to extract
from the comment in that file, sorry I didn't get around to adding that yet!). Specify an image to sign; be default it will push the
signed image back with the same tag, but you can also specify a new tag to push to with the `-put` option. The prototype expacts
you to be using keychain authentication.

```
./sign -keyfile ~/.ssh/secretive.pub -I justin@specialbusservice.com -put justinjustin/sign:signed justinjustin/sign:latest
```

You can examine the index to see the annotations.

For verification you need an allowed keys file, which is just a list of identifiers and public keys to use for them. If you
want to verify the image above you can use the following file which has my public key

```
justin.cormack@docker.com ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBIJ+nWeViJpSahy2q6l/nfDVX/0kkExQKIHWI73E/ZAy0i3ljzjetox6gYPhyYC/W99TVkXlXJa29k8f9CKeyRI= secretive-key-github@secretive.eel.local

```

## I want to use references

You can still use this format for simple references by tag, eg you have an unsigned index, but you could push the signed one to
`<digest>.sig` or some such convention.

There is a large advantage to using a full index with signatures, in that verifying the signatures with this scheme will verify
the desscriptor you are going to use to pull the image. This is a necessary part of validation and is easier for the client to
so if it just gets a single index to validate. For references I would recomemnd that we include the full index data in the
reference for this reason. 

## I want to sign SBOMs

I think the SBOM should be stored as a manifest entry in the index too, with an annotation referencing the image it is for, and
then you could sign them with this schema unmodified, and easily look them up in the index.

## I don't want to use this tool

It is just a prototype, this could easily be built into other tooling.

