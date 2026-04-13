package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc/codes"
	grpc_status "google.golang.org/grpc/status"

	asset "github.com/buchgr/bazel-remote/v2/genproto/build/bazel/remote/asset/v1"
	pb "github.com/buchgr/bazel-remote/v2/genproto/build/bazel/remote/execution/v2"

	"github.com/buchgr/bazel-remote/v2/cache"
)

// FetchServer implementation

var errNilFetchBlobRequest = grpc_status.Error(codes.InvalidArgument,
	"expected a non-nil *FetchBlobRequest")

var resourceExhaustedResponse = asset.FetchBlobResponse{
	Status: &status.Status{
		Code:    int32(codes.ResourceExhausted),
		Message: "Storage appears to be falling behind",
	},
}

const remoteAssetAPILogPrefix = "[REMOTE_ASSET_API]"

var netrcPathFunc = netrcPath

func (s *grpcServer) remoteAssetInfof(format string, args ...any) {
	s.accessLogger.Printf(remoteAssetAPILogPrefix+" "+format, args...)
}

func (s *grpcServer) remoteAssetErrorf(format string, args ...any) {
	s.errorLogger.Printf(remoteAssetAPILogPrefix+" "+format, args...)
}

func (s *grpcServer) FetchBlob(ctx context.Context, req *asset.FetchBlobRequest) (*asset.FetchBlobResponse, error) {

	var sha256Str string

	// Q: which combinations of qualifiers to support?
	// * simple file, identified by sha256 SRI AND/OR recognisable URL
	// * git repository, identified by ???
	// * go repository, identified by tag/branch/???

	// "strong" identifiers:
	// checksum.sri -> direct lookup for sha256 (easy), indirect lookup for
	//     others (eg sha256 of the SRI hash).
	// vcs.commit + .git extension -> indirect lookup? or sha1 lookup?
	//     But this could waste a lot of space.
	//
	// "weak" identifiers:
	// vcs.branch + .git extension -> indirect lookup, with timeout check
	//    directory: limit one of the vcs.* returns
	//               insert to tree into the CAS?
	//
	//    git archive --format=tar --remote=http://foo/bar.git ref dir...

	// For TTL items, we need another (persistent) index, eg BadgerDB?
	// key -> CAS sha256 + timestamp
	// Should we place a limit on the size of the index?

	if req == nil {
		return nil, errNilFetchBlobRequest
	}

	s.remoteAssetInfof("FetchBlob request received: uris=%d qualifiers=%d", len(req.GetUris()), len(req.GetQualifiers()))

	globalHeader := http.Header{}

	uriSpecificHeaders := make(map[int]http.Header)

	for _, q := range req.GetQualifiers() {
		if q == nil {
			return &asset.FetchBlobResponse{
				Status: &status.Status{
					Code:    int32(codes.InvalidArgument),
					Message: "unexpected nil qualifier in FetchBlobRequest",
				},
			}, nil
		}

		const QualifierHTTPHeaderPrefix = "http_header:"
		const QualifierHTTPHeaderUrlPrefix = "http_header_url:"

		if strings.HasPrefix(q.Name, QualifierHTTPHeaderPrefix) {
			key := q.Name[len(QualifierHTTPHeaderPrefix):]

			globalHeader[key] = strings.Split(q.Value, ",")
			continue
		} else if strings.HasPrefix(q.Name, QualifierHTTPHeaderUrlPrefix) {
			idxAndKey := q.Name[len(QualifierHTTPHeaderUrlPrefix):]
			parts := strings.Split(idxAndKey, ":")
			if len(parts) != 2 {
				s.remoteAssetErrorf("invalid http_header_url qualifier: %q", idxAndKey)
				continue
			}

			uriIndex, err := strconv.Atoi(parts[0])
			if err != nil {
				s.remoteAssetErrorf("failed to parse URI index as int: %v", err)
				continue
			}

			if uriIndex < 0 || uriIndex >= len(req.GetUris()) {
				s.remoteAssetErrorf("URI index for header is out of range [0 - %d]: %d", len(req.GetUris())-1, uriIndex)
				continue
			}

			if _, found := uriSpecificHeaders[uriIndex]; !found {
				uriSpecificHeaders[uriIndex] = make(http.Header)
			}
			uriSpecificHeaders[uriIndex].Add(parts[1], q.Value)

			continue
		}

		if q.Name == "checksum.sri" && strings.HasPrefix(q.Value, "sha256-") {
			// Ref: https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity

			b64hash := strings.TrimPrefix(q.Value, "sha256-")

			decoded, err := base64.StdEncoding.DecodeString(b64hash)
			if err != nil {
				s.remoteAssetErrorf("failed to base64 decode %q: %v",
					b64hash, err)
				continue
			}

			sha256Str = hex.EncodeToString(decoded)
			s.remoteAssetInfof("repository asset checksum resolved: sha256=%s", sha256Str)

			found, size := s.cache.Contains(ctx, cache.CAS, sha256Str, -1)
			if !found {
				s.remoteAssetInfof("repository asset not found in cache: sha256=%s", sha256Str)
				continue
			}

			if size < 0 {
				s.remoteAssetInfof("repository asset found in cache, resolving size from backend: sha256=%s", sha256Str)
				// We don't know the size yet (bad http backend?).
				r, actualSize, err := s.cache.Get(ctx, cache.CAS, sha256Str, -1, 0)
				if r != nil {
					defer func() { _ = r.Close() }()
				}
				if err != nil || actualSize < 0 {
					s.remoteAssetErrorf("failed to get CAS %s from proxy backend size: %d err: %v",
						sha256Str, actualSize, err)
					continue
				}
				size = actualSize
			}

			s.remoteAssetInfof("repository asset found in cache: sha256=%s size=%d", sha256Str, size)

			return &asset.FetchBlobResponse{
				Status: &status.Status{Code: int32(codes.OK)},
				BlobDigest: &pb.Digest{
					Hash:      sha256Str,
					SizeBytes: size,
				},
			}, nil
		}
	}

	// Cache miss.
	if sha256Str == "" {
		s.remoteAssetInfof("repository asset cache lookup skipped: no sha256 checksum qualifier provided")
	}

	// See if we can download one of the URIs.

	for uriIndex, uri := range req.GetUris() {
		s.remoteAssetInfof("attempting repository asset fetch from URI: %s", uri)
		uriSpecificHeader := globalHeader.Clone()
		if header, found := uriSpecificHeaders[uriIndex]; found {
			for key, value := range header {
				uriSpecificHeader[key] = value
			}
		}

		actualHash, size, err := s.fetchItem(ctx, uri, uriSpecificHeader, sha256Str)
		if err == nil {
			s.remoteAssetInfof("repository asset fetched and stored in cache: uri=%s sha256=%s size=%d", uri, actualHash, size)
			return &asset.FetchBlobResponse{
				Status: &status.Status{Code: int32(codes.OK)},
				BlobDigest: &pb.Digest{
					Hash:      actualHash,
					SizeBytes: size,
				},
				Uri: uri,
			}, nil
		}

		if translateGRPCErrCodeFromClient(err) == codes.ResourceExhausted {
			s.remoteAssetErrorf("repository asset fetch hit resource exhaustion: uri=%s err=%v", uri, err)
			return &resourceExhaustedResponse, nil
		}

		s.remoteAssetInfof("repository asset fetch from URI failed: uri=%s err=%v", uri, err)

		// Not a simple file. Not yet handled...
	}

	s.remoteAssetInfof("repository asset not found after checking cache and %d URI(s)", len(req.GetUris()))

	return &asset.FetchBlobResponse{
		Status: &status.Status{Code: int32(codes.NotFound)},
	}, nil
}

func (s *grpcServer) fetchItem(ctx context.Context, uri string, headers http.Header, expectedHash string) (string, int64, error) {
	u, err := url.Parse(uri)
	if err != nil {
		s.remoteAssetErrorf("unable to parse URI %s: %v", uri, err)
		return "", int64(-1), err
	}

	if u.Scheme != "http" && u.Scheme != "https" {
		s.remoteAssetErrorf("unsupported URI: %s", uri)
		return "", int64(-1), fmt.Errorf("unknown URL scheme: %q", u.Scheme)
	}

	req, err := http.NewRequest(http.MethodGet, uri, nil)
	if err != nil {
		s.remoteAssetErrorf("failed to create http.Request for %s: %v", uri, err)
		return "", int64(-1), err
	}

	req.Header = headers
	s.applyNetrcCredentials(req)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		s.remoteAssetErrorf("failed to GET URI %s: %v", uri, err)
		return "", int64(-1), err
	}
	defer func() { _ = resp.Body.Close() }()
	rc := resp.Body

	s.remoteAssetInfof("repository asset HTTP fetch response: uri=%s status=%s", uri, resp.Status)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", int64(-1), fmt.Errorf("unsuccessful HTTP status code: %d", resp.StatusCode)
	}

	expectedSize := resp.ContentLength
	if expectedHash == "" || expectedSize < 0 {
		// We can't call Put until we know the hash and size.

		data, err := io.ReadAll(resp.Body)
		if err != nil {
			s.remoteAssetErrorf("failed to read data from %s: %v", uri, err)
			return "", int64(-1), err
		}

		expectedSize = int64(len(data))
		hashBytes := sha256.Sum256(data)
		hashStr := hex.EncodeToString(hashBytes[:])

		if expectedHash != "" && hashStr != expectedHash {
			s.remoteAssetErrorf("URI data has hash %s, expected %s",
				hashStr, expectedHash)
			return "", int64(-1), fmt.Errorf("URI data has hash %s, expected %s", hashStr, expectedHash)
		}

		expectedHash = hashStr
		rc = io.NopCloser(bytes.NewReader(data))
	}

	err = s.cache.Put(ctx, cache.CAS, expectedHash, expectedSize, rc)
	if err != nil && err != io.EOF {
		s.remoteAssetErrorf("failed to store %s in cache: %v", expectedHash, err)
		return "", int64(-1), err
	}

	return expectedHash, expectedSize, nil
}

type netrcCredentials struct {
	login    string
	password string
}

func (s *grpcServer) applyNetrcCredentials(req *http.Request) {
	if req.URL == nil {
		return
	}

	if req.Header.Get("Authorization") != "" {
		s.remoteAssetInfof("skipping .netrc credentials because Authorization header is already set: host=%s", req.URL.Host)
		return
	}

	if req.URL.User != nil {
		s.remoteAssetInfof("skipping .netrc credentials because URI already contains user info: host=%s", req.URL.Host)
		return
	}

	creds, source, err := lookupNetrcCredentials(req.URL.Hostname())
	if err != nil {
		s.remoteAssetErrorf("failed to read .netrc credentials for host=%s: %v", req.URL.Hostname(), err)
		return
	}
	if creds == nil {
		s.remoteAssetInfof("no .netrc credentials found for host=%s", req.URL.Hostname())
		return
	}

	req.SetBasicAuth(creds.login, creds.password)
	s.remoteAssetInfof("using .netrc credentials for host=%s from %s", req.URL.Hostname(), source)
}

func lookupNetrcCredentials(host string) (*netrcCredentials, string, error) {
	path, err := netrcPathFunc()
	if err != nil {
		return nil, "", err
	}
	if path == "" {
		return nil, "", nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, "", nil
		}
		return nil, "", err
	}

	tokens := strings.Fields(string(data))
	if len(tokens) == 0 {
		return nil, "", nil
	}

	var (
		matchedCreds *netrcCredentials
		defaultCreds *netrcCredentials
		currentHost  string
		currentCreds *netrcCredentials
	)

	commitEntry := func() {
		if currentCreds == nil || currentCreds.login == "" || currentCreds.password == "" {
			currentHost = ""
			currentCreds = nil
			return
		}

		if currentHost == "default" {
			creds := *currentCreds
			defaultCreds = &creds
		} else if currentHost == host {
			creds := *currentCreds
			matchedCreds = &creds
		}

		currentHost = ""
		currentCreds = nil
	}

	for i := 0; i < len(tokens); i++ {
		switch tokens[i] {
		case "machine", "default":
			commitEntry()

			if tokens[i] == "default" {
				currentHost = "default"
				currentCreds = &netrcCredentials{}
				continue
			}

			if i+1 >= len(tokens) {
				return nil, "", fmt.Errorf("malformed .netrc: missing machine name")
			}
			i++
			currentHost = tokens[i]
			currentCreds = &netrcCredentials{}
		case "login":
			if currentCreds == nil || i+1 >= len(tokens) {
				continue
			}
			i++
			currentCreds.login = tokens[i]
		case "password":
			if currentCreds == nil || i+1 >= len(tokens) {
				continue
			}
			i++
			currentCreds.password = tokens[i]
		case "account", "macdef":
			if i+1 < len(tokens) {
				i++
			}
		}
	}
	commitEntry()

	if matchedCreds != nil {
		return matchedCreds, path, nil
	}

	if defaultCreds == nil || defaultCreds.login == "" || defaultCreds.password == "" {
		return nil, "", nil
	}

	return defaultCreds, path, nil
}

func netrcPath() (string, error) {
	if path := os.Getenv("NETRC"); path != "" {
		return path, nil
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	if home == "" {
		return "", nil
	}

	return filepath.Join(home, ".netrc"), nil
}

func (s *grpcServer) FetchDirectory(context.Context, *asset.FetchDirectoryRequest) (*asset.FetchDirectoryResponse, error) {
	return nil, nil
}

/* PushServer implementation
func (s *grpcServer) PushBlob(context.Context, *asset.PushBlobRequest) (*asset.PushBlobResponse, error) {
	return nil, nil
}

func (s *grpcServer) PushDirectory(context.Context, *asset.PushDirectoryRequest) (*asset.PushDirectoryResponse, error) {
	return nil, nil
}
*/
