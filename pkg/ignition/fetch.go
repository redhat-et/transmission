package ignition

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	configErrors "github.com/coreos/ignition/v2/config/shared/errors"
	ignutil "github.com/coreos/ignition/v2/config/util"
	ign3types "github.com/coreos/ignition/v2/config/v3_4/types"
	"github.com/redhat-et/transmission/pkg/util"
	"github.com/vincent-petithory/dataurl"
)

var (
	ErrSchemeUnsupported = errors.New("unsupported source scheme")
)

func IsExternalResource(r ign3types.Resource) bool {
	if r.Source == nil {
		return false
	}
	u, err := url.Parse(*r.Source)
	if err != nil {
		return false
	}
	return (u.Scheme != "" && u.Scheme != "data")
}

func EmbedAllResources(ign *ign3types.Config) error {
	for i := range ign.Storage.Files {
		f := &ign.Storage.Files[i]
		if !IsExternalResource(f.Contents) {
			continue
		}

		buf, err := FetchToBuffer(f)
		if err != nil {
			return fmt.Errorf("failed to download remote resource %s: %w", *f.Contents.Source, err)
		}

		f.Contents.Source = ignutil.StrToPtr(dataurl.EncodeBytes(buf))
		f.Contents.Compression = nil
		f.Contents.Verification.Hash = nil
	}
	return nil
}

func FetchToBuffer(f *ign3types.File) ([]byte, error) {
	u, err := url.Parse(*f.Contents.Source)
	if err != nil {
		return nil, err
	}

	var src io.Reader
	switch u.Scheme {
	case "http", "https":
		src, err = httpReader(u)
	case "data":
		src, err = dataURLReader(u)
	case "file":
		src, err = fileReader(u)
	case "":
		return nil, nil
	default:
		return nil, ErrSchemeUnsupported
	}
	if err != nil {
		return nil, err
	}

	dest := new(bytes.Buffer)
	err = decompressCopyHashAndVerify(dest, src,
		util.DefaultIfNil(f.Contents.Compression, ""),
		util.DefaultIfNil(f.Contents.Verification.Hash, ""))
	return dest.Bytes(), err
}

func httpReader(u *url.URL) (io.Reader, error) {
	resp, err := http.Get(u.String())
	if err != nil {
		return nil, err
	}
	return resp.Body, nil
}

func dataURLReader(u *url.URL) (io.Reader, error) {
	url, err := dataurl.DecodeString(u.String())
	if err != nil {
		return nil, err
	}
	return bytes.NewBuffer(url.Data), nil
}

func fileReader(u *url.URL) (io.Reader, error) {
	return os.Open(u.Path)
}

// adapted from Ignition's fetch.go
func getDecompressor(r io.Reader, compression string) (io.ReadCloser, error) {
	switch compression {
	case "":
		return io.NopCloser(r), nil
	case "gzip":
		return gzip.NewReader(r)
	default:
		return nil, configErrors.ErrCompressionInvalid
	}
}

// adapted from Ignition's fetch.go
func decompressCopyHashAndVerify(dest io.Writer, src io.Reader, compression string, hash string) error {
	decompressor, err := getDecompressor(src, compression)
	if err != nil {
		return err
	}
	defer decompressor.Close()

	hasher, expectedSum, err := getHasherAndExpectedSum(hash)
	if err != nil {
		return err
	}
	if hasher != nil {
		hasher.Reset()
		dest = io.MultiWriter(dest, hasher)
	}

	_, err = io.Copy(dest, decompressor)
	if err != nil {
		return err
	}

	if hasher != nil {
		calculatedSum := hasher.Sum(nil)
		if !bytes.Equal(calculatedSum, expectedSum) {
			return ErrHashMismatch{
				Calculated: hex.EncodeToString(calculatedSum),
				Expected:   hex.EncodeToString(expectedSum),
			}
		}
	}
	return nil
}

func getHasherAndExpectedSum(verification string) (hash.Hash, []byte, error) {
	if verification == "" {
		return nil, nil, nil
	}

	parts := strings.SplitN(verification, "-", 2)
	if len(parts) != 2 {
		return nil, nil, ErrHashMalformed
	}

	expectedSum, err := hex.DecodeString(parts[1])
	if err != nil {
		return nil, nil, err
	}

	switch parts[0] {
	case "sha512":
		return sha512.New(), expectedSum, nil
	case "sha256":
		return sha256.New(), expectedSum, nil
	default:
		return nil, nil, ErrHashUnrecognized
	}
}
