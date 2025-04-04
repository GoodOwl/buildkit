package integration

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/shlex"
	"github.com/moby/buildkit/util/bklog"
	"github.com/pkg/errors"
)

const buildkitdConfigFile = "buildkitd.toml"

const maxSandboxTimeout = 5 * time.Minute

type sandbox struct {
	Backend

	logs       map[string]*bytes.Buffer
	cleanup    *MultiCloser
	mv         matrixValue
	ctx        context.Context
	cdiSpecDir string
	name       string
}

func (sb *sandbox) Name() string {
	return sb.name
}

func (sb *sandbox) Context() context.Context {
	return sb.ctx
}

func (sb *sandbox) CDISpecDir() string {
	return sb.cdiSpecDir
}

func (sb *sandbox) Logs() map[string]*bytes.Buffer {
	return sb.logs
}

func (sb *sandbox) PrintLogs(t *testing.T) {
	PrintLogs(sb.logs, t.Log)
}

func (sb *sandbox) ClearLogs() {
	sb.logs = make(map[string]*bytes.Buffer)
}

func (sb *sandbox) NewRegistry() (string, error) {
	url, cl, err := NewRegistry("")
	if err != nil {
		return "", err
	}
	sb.cleanup.Append(cl)
	return url, nil
}

func (sb *sandbox) Cmd(args ...string) *exec.Cmd {
	if len(args) == 1 {
		// \\ being stripped off for Windows paths, convert to unix style
		args[0] = strings.ReplaceAll(args[0], "\\", "/")
		if split, err := shlex.Split(args[0]); err == nil {
			args = split
		}
	}
	cmd := exec.Command("buildctl", args...)
	cmd.Env = append(cmd.Env, os.Environ()...)
	cmd.Env = append(cmd.Env, "BUILDKIT_HOST="+sb.Address())
	if v := os.Getenv("GO_TEST_COVERPROFILE"); v != "" {
		coverDir := filepath.Join(filepath.Dir(v), "helpers")
		cmd.Env = append(cmd.Env, "GOCOVERDIR="+coverDir)
	}
	return cmd
}

func (sb *sandbox) Value(k string) any {
	return sb.mv.values[k].value
}

func newSandbox(ctx context.Context, t *testing.T, w Worker, mirror string, mv matrixValue) (s Sandbox, cl func() error, err error) {
	cfg := &BackendConfig{
		Logs: make(map[string]*bytes.Buffer),
	}

	for _, v := range mv.values {
		if u, ok := v.value.(ConfigUpdater); ok {
			cfg.DaemonConfig = append(cfg.DaemonConfig, u)
		}
	}

	if mirror != "" {
		cfg.DaemonConfig = append(cfg.DaemonConfig, withMirrorConfig(mirror))
	}

	deferF := &MultiCloser{}
	cl = deferF.F()

	defer func() {
		if err != nil {
			deferF.F()()
			cl = nil
		}
	}()

	cdiSpecDir, err := os.MkdirTemp("", "buildkit-integration-cdi")
	if err != nil {
		return nil, nil, errors.Wrap(err, "cannot create cdi spec dir")
	}
	deferF.Append(func() error {
		return os.RemoveAll(cdiSpecDir)
	})
	cfg.CDISpecDir = cdiSpecDir

	b, closer, err := w.New(ctx, cfg)
	if err != nil {
		return nil, nil, errors.Wrap(err, "creating worker")
	}
	deferF.Append(closer)

	ctx, cancel := context.WithCancelCause(ctx)

	go func() {
		timeout := maxSandboxTimeout
		if strings.Contains(t.Name(), "ExtraTimeout") {
			timeout *= 3
		}
		timeoutContext, cancelTimeout := context.WithTimeoutCause(ctx, timeout, errors.WithStack(context.DeadlineExceeded))
		defer cancelTimeout()
		<-timeoutContext.Done()
		select {
		case <-ctx.Done():
			return
		default:
			t.Logf("sandbox timeout reached, stopping worker")
			if addr := b.DebugAddress(); addr != "" {
				printBuildkitdDebugLogs(t, addr)
			}
			cancel(errors.WithStack(context.Canceled))
		}
	}()

	return &sandbox{
		Backend:    b,
		logs:       cfg.Logs,
		cleanup:    deferF,
		mv:         mv,
		ctx:        ctx,
		cdiSpecDir: cfg.CDISpecDir,
		name:       w.Name(),
	}, cl, nil
}

func printBuildkitdDebugLogs(t *testing.T, addr string) {
	if !strings.HasPrefix(addr, socketScheme) {
		t.Logf("invalid debug address %q", addr)
		return
	}

	client := &http.Client{Transport: &http.Transport{DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
		return dialPipe(strings.TrimPrefix(addr, socketScheme))
	}}}

	resp, err := client.Get("http://localhost/debug/pprof/goroutine?debug=2") //nolint:noctx // never cancel
	if err != nil {
		t.Fatalf("failed to get debug logs: %v", err)
		return
	}
	defer resp.Body.Close()
	dt, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read debug logs: %v", err)
		return
	}
	t.Logf("buildkitd debug logs:\n%s", dt)
}

func RootlessSupported(uid int) bool {
	cmd := exec.Command("sudo", "-u", fmt.Sprintf("#%d", uid), "-i", "--", "exec", "unshare", "-U", "true") //nolint:gosec // test utility
	b, err := cmd.CombinedOutput()
	if err != nil {
		bklog.L.Warnf("rootless mode is not supported on this host: %v (%s)", err, string(b))
		return false
	}
	return true
}

func PrintLogs(logs map[string]*bytes.Buffer, f func(args ...any)) {
	for name, l := range logs {
		f(name)
		s := bufio.NewScanner(l)
		for s.Scan() {
			f(s.Text())
		}
	}
}

func FormatLogs(m map[string]*bytes.Buffer) string {
	var ss []string
	for k, b := range m {
		if b != nil {
			ss = append(ss, fmt.Sprintf("%q:%q", k, b.String()))
		}
	}
	return strings.Join(ss, ",")
}

func CheckFeatureCompat(t *testing.T, sb Sandbox, features map[string]struct{}, reason ...string) {
	t.Helper()
	if err := HasFeatureCompat(t, sb, features, reason...); err != nil {
		t.Skip(err.Error())
	}
}

func HasFeatureCompat(t *testing.T, sb Sandbox, features map[string]struct{}, reason ...string) error {
	t.Helper()
	if len(reason) == 0 {
		t.Fatal("no reason provided")
	}
	var ereasons []string
	for _, r := range reason {
		if _, ok := features[r]; ok {
			if !sb.Supports(r) {
				ereasons = append(ereasons, r)
			}
		} else {
			sb.ClearLogs()
			t.Fatalf("unknown reason %q to skip test", r)
		}
	}
	if len(ereasons) > 0 {
		return errors.Errorf("%s worker can not currently run this test due to missing features (%s)", sb.Name(), strings.Join(ereasons, ", "))
	}
	return nil
}
