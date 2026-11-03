# Tachograph Go

[![PkgGoDev](https://pkg.go.dev/badge/github.com/way-platform/tachograph-go)](https://pkg.go.dev/github.com/way-platform/tachograph-go)
[![GoReportCard](https://goreportcard.com/badge/github.com/way-platform/tachograph-go)](https://goreportcard.com/report/github.com/way-platform/tachograph-go)
[![CI](https://github.com/way-platform/tachograph-go/actions/workflows/release.yaml/badge.svg)](https://github.com/way-platform/tachograph-go/actions/workflows/release.yaml)

A Go SDK and CLI tool for working with Tachograph data (.DDD files).

## Specification

This SDK implements parsing of downloaded tachograph data, according to [the requirements for the construction, testing, installation, operation and repair of tachographs and their components](https://eur-lex.europa.eu/eli/reg_impl/2016/799/oj/eng).

## Features

This library provides a comprehensive set of tools for working with Tachograph data, from raw binary parsing to anonymization and serialization.

```go
// 1. Unmarshal the raw .DDD file content into a RawFile object.
rawFile, err := tachograph.Unmarshal(dddBytes)
if err != nil {
    log.Fatalf("failed to unmarshal: %v", err)
}

// 2. Authenticate the signatures within the RawFile against the embedded ERCA roots.
authenticatedRawFile, err := tachograph.Authenticate(context.Background(), rawFile, time.Now())
if err != nil {
    log.Fatalf("failed to authenticate: %v", err)
}

// 3. Parse the authenticated RawFile into a File.
parsedFile, err := tachograph.Parse(authenticatedRawFile)
if err != nil {
    log.Fatalf("failed to parse: %v", err)
}

// 4. Anonymize personal data in the parsed File.
anonymizedFile, err := tachograph.Anonymize(parsedFile)
if err != nil {
    log.Fatalf("failed to anonymize: %v", err)
}

// 5. Marshal the file back into the binary .DDD format.
marshalledBytes, err := tachograph.Marshal(anonymizedFile)
if err != nil {
    log.Fatalf("failed to marshal: %v", err)
}
```

### Unmarshalling

[`tachograph.Unmarshal`](https://pkg.go.dev/github.com/way-platform/tachograph-go#Unmarshal) parses raw `.DDD` byte arrays into a [`tachographv1.RawFile`](https://pkg.go.dev/github.com/way-platform/tachograph-go/proto/gen/go/wayplatform/connect/tachograph/v1#RawFile) object.

### Authenticating

[`tachograph.AuthenticateOptions`](https://pkg.go.dev/github.com/way-platform/tachograph-go#AuthenticateOptions) verifies a [`tachographv1.RawFile`](https://pkg.go.dev/github.com/way-platform/tachograph-go/proto/gen/go/wayplatform/connect/tachograph/v1#RawFile) and sets an `Authentication` on every record: `VERIFIED`, `UNSIGNED` for records the regulation leaves unsigned, or why the record isn't verified (`DATA_SIGNATURE_INVALID`, `SIGNATURE_MISSING`, `CERTIFICATE_VERIFICATION_FAILED`, `CERTIFICATE_REVOKED`, `CERTIFICATE_UNTRUSTED`, `CERTIFICATE_MISSING`, `CERTIFICATE_VALIDITY_UNKNOWN`), with the chain's certificates, a VU's signing time or a card's signing window, and a `detail`. It returns an error only for input it can't process.

- `CertificateResolver` is required. [`NewCertificateResolver`](https://pkg.go.dev/github.com/way-platform/tachograph-go#NewCertificateResolver) builds one from the ERCA keys, root and link certificates and revoked MSCA certificates JRC publishes; [`DefaultCertificateResolver`](https://pkg.go.dev/github.com/way-platform/tachograph-go#DefaultCertificateResolver) trusts the ERCA Gen1 key and Gen2(1) root embedded in the library. Verification never uses the network.
- `ReceivedAt` is required: a VU download's overview may be signed at most a day later, and a card download's signing window ends at it. A card's certificate valid for only part of that window is `CERTIFICATE_VALIDITY_UNKNOWN`, and so is every other transfer of a VU download whose overview signature, which covers its signing time, doesn't verify.
- A revoked MSCA certificate is listed as JRC publishes it and revokes its CHR, which a chain reports once the MSCA certificate has verified.

The [`tachographtest`](https://pkg.go.dev/github.com/way-platform/tachograph-go/tachographtest) package generates test PKIs and signs VU and card downloads with them, for tests.

### Parsing

[`tachograph.Parse`](https://pkg.go.dev/github.com/way-platform/tachograph-go#Parse) turns a [`tachographv1.RawFile`](https://pkg.go.dev/github.com/way-platform/tachograph-go/proto/gen/go/wayplatform/connect/tachograph/v1#RawFile) into a [`tachographv1.File`](https://pkg.go.dev/github.com/way-platform/tachograph-go/proto/gen/go/wayplatform/connect/tachograph/v1#File), with meaningful, high-level structures like driver activities and events, making the data easy to analyze.

### Anonymizing

[`tachograph.Anonymize`](https://pkg.go.dev/github.com/way-platform/tachograph-go#Anonymize) removes or obscures personal data from a [`tachographv1.File`](https://pkg.go.dev/github.com/way-platform/tachograph-go/proto/gen/go/wayplatform/connect/tachograph/v1#File) - making the data usable for unit testing

### Marshalling

[`tachograph.Marshal`](https://pkg.go.dev/github.com/way-platform/tachograph-go#Marshal) serializes a [`tachographv1.File`](https://pkg.go.dev/github.com/way-platform/tachograph-go/proto/gen/go/wayplatform/connect/tachograph/v1#File) back into the binary `.DDD` format.

## CLI

```bash
$ tachograph

  Tachograph CLI

  USAGE

    tachograph [command] [--flags]

  .DDD FILES

    parse [file ...] [--flags]  Parse .DDD files

  UTILS

    completion [command]        Generate the autocompletion script for the specified shell
    help [command]              Help about any command

  FLAGS

    -h --help                   Help for tachograph
    -v --version                Version for tachograph

```

## Alternatives

This SDK draws inspiration from other tachograph SDKs, including:

- [traconiq/tachoparser](https://github.com/traconiq/tachoparser)
- [jugglingcats/tachograph-reader](https://github.com/jugglingcats/tachograph-reader)
