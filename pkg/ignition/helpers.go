// adapted from https://github.com/openshift/machine-config-operator/blob/master/pkg/controller/common/helpers.go
package ignition

import (
	// 	"bufio"
	"bytes"
	"compress/gzip"

	// 	"encoding/base64"
	// 	"errors"
	"fmt"
	"io"

	// 	"io/fs"
	// 	"os"
	"reflect"

	// 	"strings"
	// 	"text/template"

	ign3 "github.com/coreos/ignition/v2/config/v3_4"
	ign3types "github.com/coreos/ignition/v2/config/v3_4/types"
	"github.com/golang/glog"
	"github.com/vincent-petithory/dataurl"
	// 	"github.com/vincent-petithory/dataurl"
)

// // Gates whether or not the MCO uses the new format base OS container image by default
// var UseNewFormatImageByDefault = true

// // strToPtr converts the input string to a pointer to itself
// func strToPtr(s string) *string {
// 	return &s
// }

// // bootToPtr converts the input boolean to a pointer to itself
// func boolToPtr(b bool) *bool {
// 	return &b
// }

// // NewIgnConfig returns an empty ignition config with version set as latest version
// func NewIgnConfig() ign3types.Config {
// 	return ign3types.Config{
// 		Ignition: ign3types.Ignition{
// 			Version: ign3types.MaxVersion.String(),
// 		},
// 	}
// }

// DecodeIgnitionFileContents returns uncompressed, decoded inline file contents.
// This function does not handle remote resources; it assumes they have already
// been fetched.
func DecodeIgnitionFileContents(source, compression *string) ([]byte, error) {
	var contentsBytes []byte

	// To allow writing of "empty" files we'll allow source to be nil
	if source != nil {
		source, err := dataurl.DecodeString(*source)
		if err != nil {
			return []byte{}, fmt.Errorf("could not decode file content string: %w", err)
		}
		if compression != nil {
			switch *compression {
			case "":
				contentsBytes = source.Data
			case "gzip":
				reader, err := gzip.NewReader(bytes.NewReader(source.Data))
				if err != nil {
					return []byte{}, fmt.Errorf("could not create gzip reader: %w", err)
				}
				defer reader.Close()
				contentsBytes, err = io.ReadAll(reader)
				if err != nil {
					return []byte{}, fmt.Errorf("failed decompressing: %w", err)
				}
			default:
				return []byte{}, fmt.Errorf("unsupported compression type %q", *compression)
			}
		} else {
			contentsBytes = source.Data
		}
	}
	return contentsBytes, nil
}

// // InSlice search for an element in slice and return true if found, otherwise return false
// func InSlice(elem string, slice []string) bool {
// 	for _, k := range slice {
// 		if k == elem {
// 			return true
// 		}
// 	}
// 	return false
// }

// ParseAndConvertConfig parses rawIgn for both V2 and V3 ignition configs and returns
// a V3 or an error.
func ParseAndConvertConfig(rawIgn []byte) (ign3types.Config, error) {
	ignConfig, _, err := ign3.Parse(rawIgn)
	if err != nil {
		return ign3types.Config{}, fmt.Errorf("failed to parse Ignition config: %w", err)
	}
	return ignConfig, err
}

// // Internal error used for base64-decoding and gunzipping Ignition configs
// var errConfigNotGzipped = fmt.Errorf("ignition config not gzipped")

// // Decode, decompress, and deserialize an Ignition config file.
// func ParseAndConvertGzippedConfig(rawIgn []byte) (ign3types.Config, error) {
// 	// Try to decode and decompress our payload
// 	out, err := decodeAndDecompressPayload(bytes.NewReader(rawIgn))
// 	if err == nil {
// 		// Our payload was decoded and decompressed, so parse it as Ignition.
// 		glog.V(2).Info("ignition config was base64-decoded and gunzipped successfully")
// 		return ParseAndConvertConfig(out)
// 	}

// 	// Our Ignition config is not base64-encoded, which means it might only be gzipped:
// 	// e.g.: $ gzip -9 ign_config.json
// 	var base64Err base64.CorruptInputError
// 	if errors.As(err, &base64Err) {
// 		glog.V(2).Info("ignition config was not base64 encoded, trying to gunzip ignition config")
// 		out, err = decompressPayload(bytes.NewReader(rawIgn))
// 		if err == nil {
// 			// We were able to decompress our payload, so let's try parsing it
// 			glog.V(2).Info("ignition config was gunzipped successfully")
// 			return ParseAndConvertConfig(out)
// 		}
// 	}

// 	// Our Ignition config is not gzipped, so let's try to serialize the raw Ignition directly.
// 	if errors.Is(err, errConfigNotGzipped) {
// 		glog.V(2).Info("ignition config was not gzipped")
// 		return ParseAndConvertConfig(rawIgn)
// 	}

// 	return ign3types.Config{}, fmt.Errorf("unable to read ignition config: %w", err)
// }

// // Attempts to base64-decode and/or decompresses a given byte array.
// func decodeAndDecompressPayload(r io.Reader) ([]byte, error) {
// 	// Wrap the io.Reader in a base64 decoder (which implements io.Reader)
// 	base64Dec := base64.NewDecoder(base64.StdEncoding, r)
// 	out, err := decompressPayload(base64Dec)
// 	if err == nil {
// 		return out, nil
// 	}

// 	return nil, fmt.Errorf("unable to decode and decompress payload: %w", err)
// }

// // Checks if a given io.Reader contains known gzip headers and if so, gunzips
// // the contents.
// func decompressPayload(r io.Reader) ([]byte, error) {
// 	// Wrap our io.Reader in a bufio.Reader. This allows us to peek ahead to
// 	// determine if we have a valid gzip archive.
// 	in := bufio.NewReader(r)
// 	headerBytes, err := in.Peek(2)
// 	if err != nil {
// 		return nil, fmt.Errorf("could not peek: %w", err)
// 	}

// 	// gzipped files have a header in the first two bytes which contain a magic
// 	// number that indicate they are gzipped. We check if these magic numbers are
// 	// present as a quick and easy way to determine if our payload is gzipped.
// 	//
// 	// See: https://cs.opensource.google/go/go/+/refs/tags/go1.19:src/compress/gzip/gunzip.go;l=20-21
// 	if headerBytes[0] != 0x1f && headerBytes[1] != 0x8b {
// 		return nil, errConfigNotGzipped
// 	}

// 	gz, err := gzip.NewReader(in)
// 	if err != nil {
// 		return nil, fmt.Errorf("initialize gzip reader failed: %w", err)
// 	}

// 	defer gz.Close()

// 	data, err := io.ReadAll(gz)
// 	if err != nil {
// 		return nil, fmt.Errorf("decompression failed: %w", err)
// 	}

// 	return data, nil
// }

// CalculateConfigFileDiffs compares the files present in two ignition configurations and returns the list of files
// that are different between them
func CalculateConfigFileDiffs(oldIgnConfig, newIgnConfig *ign3types.Config) []string {
	// Go through the files and see what is new or different
	oldFileSet := make(map[string]ign3types.File)
	for _, f := range oldIgnConfig.Storage.Files {
		oldFileSet[f.Path] = f
	}
	newFileSet := make(map[string]ign3types.File)
	for _, f := range newIgnConfig.Storage.Files {
		newFileSet[f.Path] = f
	}
	diffFileSet := []string{}

	// First check if any files were removed
	for path := range oldFileSet {
		_, ok := newFileSet[path]
		if !ok {
			// debug: remove
			glog.Infof("File diff: %v was deleted", path)
			diffFileSet = append(diffFileSet, path)
		}
	}

	// Now check if any files were added/changed
	for path, newFile := range newFileSet {
		oldFile, ok := oldFileSet[path]
		if !ok {
			// debug: remove
			glog.Infof("File diff: %v was added", path)
			diffFileSet = append(diffFileSet, path)
		} else if !reflect.DeepEqual(oldFile, newFile) {
			// debug: remove
			glog.Infof("File diff: detected change to %v", newFile.Path)
			diffFileSet = append(diffFileSet, path)
		}
	}
	return diffFileSet
}

// // NewIgnFile returns a simple ignition3 file from just path and file contents.
// // It also ensures the compression field is set to the empty string, which is
// // currently required for ensuring child configs that may be merged layer
// // know that the input is not compressed.
// //
// // Note the default Ignition file mode is 0644, owned by root/root.
// func NewIgnFile(path, contents string) ign3types.File {
// 	return NewIgnFileBytes(path, []byte(contents))
// }

// // NewIgnFileBytes is like NewIgnFile, but accepts binary data
// func NewIgnFileBytes(path string, contents []byte) ign3types.File {
// 	mode := 0o644
// 	return ign3types.File{
// 		Node: ign3types.Node{
// 			Path: path,
// 		},
// 		FileEmbedded1: ign3types.FileEmbedded1{
// 			Mode: &mode,
// 			Contents: ign3types.Resource{
// 				Source:      strToPtr(dataurl.EncodeBytes(contents)),
// 				Compression: strToPtr(""),
// 			},
// 		},
// 	}
// }

// // NewIgnFileBytesOverwriting is like NewIgnFileBytes, but overwrites existing files by default
// func NewIgnFileBytesOverwriting(path string, contents []byte) ign3types.File {
// 	mode := 0o644
// 	overwrite := true
// 	return ign3types.File{
// 		Node: ign3types.Node{
// 			Path:      path,
// 			Overwrite: &overwrite,
// 		},
// 		FileEmbedded1: ign3types.FileEmbedded1{
// 			Mode: &mode,
// 			Contents: ign3types.Resource{
// 				Source:      strToPtr(dataurl.EncodeBytes(contents)),
// 				Compression: strToPtr(""), // See https://github.com/coreos/butane/issues/332
// 			},
// 		},
// 	}
// }

// // GetIgnitionFileDataByPath retrieves the file data for a specified path from a given ignition config
// func GetIgnitionFileDataByPath(config *ign3types.Config, path string) ([]byte, error) {
// 	for _, f := range config.Storage.Files {
// 		if path == f.Path {
// 			// Convert whatever we have to the actual bytes so we can inspect them
// 			if f.Contents.Source != nil {
// 				contents, err := dataurl.DecodeString(*f.Contents.Source)
// 				if err != nil {
// 					return nil, err
// 				}
// 				return contents.Data, err
// 			}
// 		}
// 	}
// 	return nil, nil
// }

// // Configures common template FuncMaps used across all renderers.
// func GetTemplateFuncMap() template.FuncMap {
// 	return template.FuncMap{
// 		"toString": strval,
// 		"indent":   indent,
// 	}
// }

// // Converts an interface to a string.
// // Copied from: https://github.com/Masterminds/sprig/blob/master/strings.go
// // Copied to remove the dependency on the Masterminds/sprig library.
// func strval(v interface{}) string {
// 	switch v := v.(type) {
// 	case string:
// 		return v
// 	case []byte:
// 		return string(v)
// 	case error:
// 		return v.Error()
// 	case fmt.Stringer:
// 		return v.String()
// 	default:
// 		return fmt.Sprintf("%v", v)
// 	}
// }

// // Indents a string n spaces.
// // Copied from: https://github.com/Masterminds/sprig/blob/master/strings.go
// // Copied to remove the dependency on the Masterminds/sprig library.
// func indent(spaces int, v string) string {
// 	pad := strings.Repeat(" ", spaces)
// 	return pad + strings.ReplaceAll(v, "\n", "\n"+pad)
// }

// // ioutil.ReadDir has been deprecated with os.ReadDir.
// // ioutil.ReadDir() used to return []fs.FileInfo but os.ReadDir() returns []fs.DirEntry.
// // Making it helper function so that we can reuse coversion of []fs.DirEntry into []fs.FileInfo
// // Implementation to fetch fileInfo is taken from https://pkg.go.dev/io/ioutil#ReadDir
// func ReadDir(path string) ([]fs.FileInfo, error) {
// 	entries, err := os.ReadDir(path)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to read dir %q: %w", path, err)
// 	}
// 	infos := make([]fs.FileInfo, 0, len(entries))
// 	for _, entry := range entries {
// 		info, err := entry.Info()
// 		if err != nil {
// 			return nil, fmt.Errorf("failed to fetch fileInfo of %q in %q: %w", entry.Name(), path, err)
// 		}
// 		infos = append(infos, info)
// 	}
// 	return infos, nil
// }
