package server

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/buchgr/bazel-remote/v2/cache/disk"
	asset "github.com/buchgr/bazel-remote/v2/genproto/build/bazel/remote/asset/v1"
	//pb "github.com/buchgr/bazel-remote/v2/genproto/build/bazel/remote/execution/v2"

	"google.golang.org/grpc/codes"

	testutils "github.com/buchgr/bazel-remote/v2/utils"
)

func TestAssetFetchBlob(t *testing.T) {
	t.Parallel()

	fixture := grpcTestSetup(t)
	defer func() { _ = os.Remove(fixture.tempdir) }()

	ts := newTestGetServer()

	hexSha256 := strings.TrimSuffix(ts.path, ".tar.gz")
	hashBytes, err := hex.DecodeString(hexSha256)
	if err != nil {
		t.Fatal(err)
	}

	req := asset.FetchBlobRequest{
		Uris: []string{
			ts.srv.URL + "/404.unrecognisedextension",
			ts.srv.URL + "/404.tar.gz",
			ts.srv.URL + "/" + ts.path, // This URL should work.
		},
		Qualifiers: []*asset.Qualifier{
			{
				Name: "checksum.sri",
				Value: "sha256-" +
					base64.StdEncoding.EncodeToString([]byte(hashBytes)),
			},
		},
	}

	resp, err := fixture.assetClient.FetchBlob(ctx, &req)
	if err != nil {
		t.Fatal(err)
	}

	if resp.Status.GetCode() != int32(codes.OK) {
		t.Fatal("expected successful fetch")
	}
	if resp.BlobDigest == nil {
		t.Fatal("expected non-bil BlobDigest")
	}
	if resp.BlobDigest.Hash != hexSha256 {
		t.Fatal("mismatching BlobDigest hash returned")
	}
}

func TestAssetFetchBlobUsesNetrcCredentials(t *testing.T) {
	blobDir := t.TempDir()
	diskCache, err := disk.New(blobDir, 1024*1024, disk.WithAccessLogger(testutils.NewSilentLogger()))
	if err != nil {
		t.Fatal(err)
	}

	accessLogs := new(bytes.Buffer)
	srv := &grpcServer{
		cache:        diskCache,
		accessLogger: log.New(accessLogs, "", 0),
		errorLogger:  testutils.NewSilentLogger(),
	}

	ts := newAuthenticatedTestGetServer("alice", "secret")
	defer ts.srv.Close()

	netrcFile := filepath.Join(t.TempDir(), ".netrc")
	netrc := fmt.Sprintf("machine %s login alice password secret\n", strings.Split(strings.TrimPrefix(ts.srv.URL, "http://"), ":")[0])
	err = os.WriteFile(netrcFile, []byte(netrc), 0o600)
	if err != nil {
		t.Fatal(err)
	}
	oldNetrcPathFunc := netrcPathFunc
	netrcPathFunc = func() (string, error) { return netrcFile, nil }
	t.Cleanup(func() { netrcPathFunc = oldNetrcPathFunc })

	resp, err := srv.FetchBlob(ctx, &asset.FetchBlobRequest{
		Uris: []string{ts.srv.URL + "/" + ts.path},
	})
	if err != nil {
		t.Fatal(err)
	}

	if resp.Status.GetCode() != int32(codes.OK) {
		t.Fatalf("expected successful fetch, got status %d", resp.Status.GetCode())
	}

	logOutput := accessLogs.String()
	if !strings.Contains(logOutput, "[REMOTE_ASSET_API] attempting repository asset fetch from URI: "+ts.srv.URL+"/"+ts.path) {
		t.Fatalf("expected repository fetch attempt log, got:\n%s", logOutput)
	}
	if !strings.Contains(logOutput, "[REMOTE_ASSET_API] using .netrc credentials for host=") {
		t.Fatalf("expected .netrc credential log, got:\n%s", logOutput)
	}
}

type testGetServer struct {
	srv *httptest.Server

	blob             []byte
	path             string
	username         string
	password         string
	requireBasicAuth bool
}

func (s *testGetServer) handler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "Unsupported method for this test",
			http.StatusMethodNotAllowed)
		return
	}

	if r.URL.Path != "/"+s.path {
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}

	if s.requireBasicAuth {
		username, password, ok := r.BasicAuth()
		if !ok || username != s.username || password != s.password {
			w.Header().Set("WWW-Authenticate", `Basic realm="test"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
	}

	w.WriteHeader(http.StatusOK)

	if r.Method == http.MethodHead {
		w.Header().Set("ContentLength", fmt.Sprintf("%d", len(s.blob)))
	}

	if r.Method == http.MethodGet {
		_, _ = w.Write(s.blob)
	}
}

func newTestGetServer() *testGetServer {
	blob, hash := testutils.RandomDataAndHash(256)

	ts := testGetServer{
		blob: blob,
		path: hash + ".tar.gz",
	}
	ts.srv = httptest.NewServer(http.HandlerFunc(ts.handler))

	return &ts
}

func newAuthenticatedTestGetServer(username, password string) *testGetServer {
	ts := newTestGetServer()
	ts.username = username
	ts.password = password
	ts.requireBasicAuth = true
	return ts
}
