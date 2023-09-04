package git

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	ignutil "github.com/coreos/ignition/v2/config/util"
	ign3config "github.com/coreos/ignition/v2/config/v3_4"
	ign3types "github.com/coreos/ignition/v2/config/v3_4/types"
	"github.com/ghodss/yaml"
	"github.com/redhat-et/transmission/pkg/ignition"
	"github.com/redhat-et/transmission/pkg/jsonpath"
	"github.com/vincent-petithory/dataurl"
)

type GitConfigProvider struct {
	StagingDir string
	URL        string
	Ref        string
	Path       string
}

func New(stagingDir string, url string, ref string, path string) *GitConfigProvider {
	return &GitConfigProvider{
		StagingDir: stagingDir,
		URL:        url,
		Ref:        ref,
		Path:       path,
	}
}

func (g *GitConfigProvider) FetchConfig(ctx context.Context, dest string) (bool, error) {
	if getConfig(g.StagingDir, "remote.origin.url") != g.URL {
		os.RemoveAll(g.StagingDir)
	}

	if !isGitRepo(g.StagingDir) {
		if err := clone(ctx, g.StagingDir, g.URL); err != nil {
			return false, fmt.Errorf("failed to clone repo: %w", err)
		}
		if err := setConfig(g.StagingDir, "pull.ff", "only"); err != nil {
			return false, fmt.Errorf("failed to set git config to pull.ff only: %w", err)
		}
	}

	if err := checkout(ctx, g.StagingDir, g.Ref); err != nil {
		return false, fmt.Errorf("failed to checkout ref %s: %w", g.Ref, err)
	}

	if err := update(ctx, g.StagingDir); err != nil {
		return false, fmt.Errorf("failed to update repo: %w", err)
	}

	ign := ign3types.Config{
		Ignition: ign3types.Ignition{
			Version: ign3types.MaxVersion.String(),
		},
	}

	for _, fpath := range listFiles(g.StagingDir) {
		if strings.HasPrefix(filepath.Base(fpath), ".git") {
			continue
		}

		if filepath.Base(fpath) == ".transmission.systemd_unit_states.yaml" {
			continue
		}

		if strings.HasSuffix(fpath, ".meta") {
			yamlData, err := os.ReadFile(filepath.Join(g.StagingDir, fpath))
			if err != nil {
				return false, fmt.Errorf("failed to read %s: %w", fpath, err)
			}

			jsonData, err := yaml.YAMLToJSON(yamlData)
			if err != nil {
				return false, fmt.Errorf("failed to convert %s to json: %w", fpath, err)
			}

			// tar+gzip compression is a transmission-proprietary extension, so it'll fail validation during parsing.
			// If it is present, remove it so the config parses again.
			var jsonObj map[string]any
			err = json.Unmarshal(jsonData, &jsonObj)
			if err != nil {
				return false, fmt.Errorf("failed to decode %s: %w", fpath, err)
			}
			origCompression, _ := jsonpath.JsonGetString(jsonObj, "contents.compression")
			if origCompression == "tar+gzip" {
				jsonpath.JsonSet(jsonObj, "contents.compression", nil)
				jsonData, err = json.Marshal(jsonObj)
				if err != nil {
					return false, fmt.Errorf("failed to encode %s with updated compression: %w", fpath, err)
				}
			}

			// continue processing as normal
			ignRaw := "{\"ignition\":{\"version\":\"3.4.0\"},\"storage\":{\"files\":[" + string(jsonData) + "]}}"
			fmt.Printf("json: %v\n", ignRaw)
			ignTemp, _, err := ign3config.Parse([]byte(ignRaw))
			if err != nil {
				return false, fmt.Errorf("failed to parse .meta file into an ignition file: %w", err)
			}

			// If the original compression was tar+gzip, download and untar the file here and add it as dataUrl
			if origCompression == "tar+gzip" {
				tempDir, err := os.MkdirTemp("", "transmission")
				if err != nil {
					return false, fmt.Errorf("failed to create temp dir: %w", err)
				}
				defer os.RemoveAll(tempDir)

				tarFilePath := filepath.Join(tempDir, "file.tar.gz")
				tarFile := ign3types.File{
					Node: ign3types.Node{
						Path: tarFilePath,
					},
					FileEmbedded1: ign3types.FileEmbedded1{
						Contents: ign3types.Resource{
							Source: ignTemp.Storage.Files[0].Contents.Source,
						},
					},
				}
				buf, err := ignition.FetchToBuffer(&tarFile)
				if err != nil {
					return false, fmt.Errorf("failed to fetch remote resource %s: %w", *tarFile.Contents.Source, err)
				}
				err = os.WriteFile(tarFilePath, buf, 0644)
				if err != nil {
					return false, fmt.Errorf("failed to write remote resource %s to %s: %w", *tarFile.Contents.Source, tarFilePath, err)
				}

				destFile := filepath.Base(ignTemp.Storage.Files[0].Path)
				_, err = execWithContextAndOutput(ctx, "tar", "-C", tempDir, "-x", "-f", tarFilePath, destFile)
				if err != nil {
					return false, fmt.Errorf("failed to untar %s: %w", tarFilePath, err)
				}

				buf, err = os.ReadFile(filepath.Join(tempDir, destFile))
				if err != nil {
					return false, fmt.Errorf("faild to read '%s' from archive: %w", destFile, err)
				}

				ignTemp.Storage.Files[0].Contents.Source = ignutil.StrToPtr(dataurl.EncodeBytes(buf))
			}

			ign.Storage.Files = append(ign.Storage.Files, ignTemp.Storage.Files[0])
			continue
		}

		abspath, err := filepath.Abs(filepath.Join(g.StagingDir, fpath))
		if err != nil {
			return false, fmt.Errorf("failed to get absolute path for %s: %w", filepath.Join(g.StagingDir, fpath), err)
		}
		stat, err := os.Lstat(abspath)
		if err != nil {
			return false, fmt.Errorf("failed to stat %s: %w", abspath, err)
		}

		source := "file://" + abspath
		ignFile := ign3types.File{
			Node: ign3types.Node{
				Path:      filepath.Join("/", fpath),
				Overwrite: ignutil.BoolToPtr(true),
			},
			FileEmbedded1: ign3types.FileEmbedded1{
				Contents: ign3types.Resource{
					Source: &source,
				},
				Mode: ignutil.IntToPtr(int(stat.Mode().Perm())),
			},
		}
		ign.Storage.Files = append(ign.Storage.Files, ignFile)
	}

	err := ignition.EmbedAllResources(&ign)
	if err != nil {
		return false, fmt.Errorf("failed to embed all resources: %w", err)
	}

	return true, ignition.Save(dest, &ign)
}

func isGitRepo(repoDir string) bool {
	_, err := execWithOutput("git", "-C", repoDir, "rev-parse", "--is-inside-work-tree")
	return err == nil
}

func getConfig(repoDir string, key string) string {
	rawOut, err := execWithOutput("git", "-C", repoDir, "config", "--get", key)
	if err != nil {
		return ""
	}
	return strings.TrimSuffix(string(rawOut), "\n")
}

func listFiles(repoDir string) []string {
	files, err := execWithOutput("git", "-C", repoDir, "ls-files")
	if err != nil {
		return []string{}
	}
	return strings.Split(strings.TrimSuffix(string(files), "\n"), "\n")
}

func setConfig(repoDir string, key string, value string) error {
	_, err := execWithOutput("git", "-C", repoDir, "config", key, value)
	return err
}

func clone(ctx context.Context, repoDir string, url string) error {
	_, err := execWithContextAndOutput(ctx, "git", "clone", "--no-checkout", url, repoDir)
	return err
}

func checkout(ctx context.Context, repoDir string, ref string) error {
	_, err := execWithContextAndOutput(ctx, "git", "-C", repoDir, "checkout", ref)
	return err
}

func update(ctx context.Context, repoDir string) error {
	_, err := execWithContextAndOutput(ctx, "git", "-C", repoDir, "pull")
	return err
}

// from https://github.com/openshift/machine-config-operator/blob/master/pkg/daemon/rpm-ostree.go
// truncate a string using runes/codepoints as limits.
// This specifically will avoid breaking a UTF-8 value.
func truncate(input string, limit int) string {
	asRunes := []rune(input)
	l := len(asRunes)

	if limit >= l {
		return input
	}

	return fmt.Sprintf("%s [%d more chars]", string(asRunes[:limit]), l-limit)
}

func execWithOutput(command string, args ...string) ([]byte, error) {
	return execWithContextAndOutput(context.TODO(), command, args...)
}

// from https://github.com/openshift/machine-config-operator/blob/master/pkg/daemon/rpm-ostree.go
func execWithContextAndOutput(ctx context.Context, command string, args ...string) ([]byte, error) {
	rawOut, err := exec.CommandContext(ctx, command, args...).Output()
	if err != nil {
		errtext := ""
		if e, ok := err.(*exec.ExitError); ok {
			// Trim to max of 256 characters
			errtext = fmt.Sprintf("\n%s", truncate(string(e.Stderr), 256))
		}
		return nil, fmt.Errorf("error running %s %s: %s%s", command, strings.Join(args, " "), err, errtext)
	}
	return rawOut, nil
}
