package main

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"
)

// Official CLI wire format: "msg_" + 12 lowercase hex + 14 alphanumeric.
var requestIDPattern = regexp.MustCompile(`^msg_[0-9a-f]{12}[A-Za-z0-9]{14}$`)

func mustIntercept(t *testing.T, headers map[string][]string) interceptResponse {
	t.Helper()
	return mustInterceptWithMeta(t, headers, nil)
}

func mustInterceptWithMeta(t *testing.T, headers map[string][]string, meta map[string]any) interceptResponse {
	t.Helper()
	raw, err := json.Marshal(interceptRequest{RequestID: "test", Headers: headers, Metadata: meta})
	if err != nil {
		t.Fatal(err)
	}
	out, err := interceptHeaders(raw)
	if err != nil {
		t.Fatal(err)
	}
	var env envelope
	if err := json.Unmarshal(out, &env); err != nil {
		t.Fatal(err)
	}
	if !env.OK {
		t.Fatalf("envelope not ok: %s", out)
	}
	var resp interceptResponse
	if err := json.Unmarshal(env.Result, &resp); err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestNilHeadersNoop(t *testing.T) {
	resp := mustIntercept(t, nil)
	if len(resp.Headers) != 0 {
		t.Fatalf("headers = %v, want empty", resp.Headers)
	}
}

// The official CLI wire fingerprint is regex-shaped: msg_ + 12 hex + 14
// alphanumeric. Many assertions below check it.
func mustMatchingRequestID(t *testing.T, headers map[string][]string) string {
	t.Helper()
	values := headers["X-Opencode-Request"]
	if len(values) != 1 {
		t.Fatalf("X-Opencode-Request = %v, want exactly one value", values)
	}
	id := values[0]
	if !requestIDPattern.MatchString(id) {
		t.Fatalf("request id %q does not match the official format", id)
	}
	return id
}

func TestExistingOpencodeSessionPreserved(t *testing.T) {
	resp := mustIntercept(t, map[string][]string{
		"x-opencode-session": {"ses_client"},
		"Session-Id":         {"should-not-win"},
	})
	if _, ok := resp.Headers["X-Opencode-Session"]; ok {
		t.Fatalf("headers = %v, want the client value untouched", resp.Headers)
	}
	if got := resp.Headers["X-Opencode-Session-Id"]; len(got) != 1 || got[0] != "ses_client" {
		t.Fatalf("session-id mirror = %v, want ses_client", resp.Headers)
	}
	if got := resp.Headers["X-Opencode-Client"]; len(got) != 1 || got[0] != defaultClientValue {
		t.Fatalf("headers = %v, want the cli fingerprint", resp.Headers)
	}
	if got := resp.Headers["X-Opencode-Project"]; len(got) != 1 || got[0] != defaultProjectValue {
		t.Fatalf("headers = %v, want the cli project scope", resp.Headers)
	}
	mustMatchingRequestID(t, resp.Headers)
}

func TestConflictingCaseVariantSessionHeadersFailClosed(t *testing.T) {
	resp := mustInterceptWithMeta(t,
		map[string][]string{
			"Session-Id": {"session-a"},
			"session-id": {"session-b"},
		},
		map[string]any{"canonical_session_id": "codex:fallback-must-not-win"})
	if len(resp.Headers) != 0 {
		t.Fatalf("headers = %v, want empty for ambiguous session headers", resp.Headers)
	}
}

func TestRepeatedEquivalentSessionHeadersAccepted(t *testing.T) {
	resp := mustIntercept(t, map[string][]string{
		"Session-Id": {"session-a", " session-a "},
		"session-id": {"session-a"},
	})
	if got := resp.Headers["X-Opencode-Session"]; len(got) != 1 || got[0] != "session-a" {
		t.Fatalf("headers = %v, want normalized session-a", resp.Headers)
	}
}

func TestInvalidSessionHeadersFailClosed(t *testing.T) {
	invalid := []string{
		"contains\rreturn",
		"contains\nnewline",
		"contains\x00nul",
		"contains" + string(rune(0x85)) + "control",
		strings.Repeat("x", maxSessionIDBytes+1),
	}
	for _, value := range invalid {
		resp := mustInterceptWithMeta(t,
			map[string][]string{
				"Session-Id":   {value},
				"X-Session-Id": {"lower-priority-must-not-win"},
			},
			map[string]any{"canonical_session_id": "codex:fallback-must-not-win"})
		if len(resp.Headers) != 0 {
			t.Fatalf("value %q: headers = %v, want empty", value, resp.Headers)
		}
	}
}

func TestCodexSessionMapped(t *testing.T) {
	resp := mustIntercept(t, map[string][]string{"Session-Id": {"codex-ses-1"}})
	got := resp.Headers["X-Opencode-Session"]
	if len(got) != 1 || got[0] != "codex-ses-1" {
		t.Fatalf("headers = %v, want x-opencode-session=codex-ses-1", resp.Headers)
	}
	if got := resp.Headers["X-Opencode-Client"]; len(got) != 1 || got[0] != defaultClientValue {
		t.Fatalf("headers = %v, want x-opencode-client=cli", resp.Headers)
	}
	if got := resp.Headers["X-Opencode-Session-Id"]; len(got) != 1 || got[0] != "codex-ses-1" {
		t.Fatalf("headers = %v, want the session-id mirror", resp.Headers)
	}
	if got := resp.Headers["X-Opencode-Project"]; len(got) != 1 || got[0] != defaultProjectValue {
		t.Fatalf("headers = %v, want x-opencode-project=global", resp.Headers)
	}
	mustMatchingRequestID(t, resp.Headers)
}

func TestUnderscoreVariantsMapped(t *testing.T) {
	for _, h := range []string{"Session_id", "Thread-Id", "Thread_id", "X-Session-Affinity", "X-Session-Id"} {
		resp := mustIntercept(t, map[string][]string{h: {"v-" + h}})
		if got := resp.Headers["X-Opencode-Session"]; len(got) != 1 || got[0] != "v-"+h {
			t.Fatalf("%s: headers = %v", h, resp.Headers)
		}
	}
}

func TestClaudeCodeSessionMapped(t *testing.T) {
	resp := mustIntercept(t, map[string][]string{"X-Claude-Code-Session-Id": {"cc-123"}})
	if got := resp.Headers["X-Opencode-Session"]; len(got) != 1 || got[0] != "cc-123" {
		t.Fatalf("headers = %v", resp.Headers)
	}
}

func TestDshSessionMapped(t *testing.T) {
	resp := mustIntercept(t, map[string][]string{"X-DeepSeek-Harness-Session-Id": {"dsh-9"}})
	if got := resp.Headers["X-Opencode-Session"]; len(got) != 1 || got[0] != "dsh-9" {
		t.Fatalf("headers = %v", resp.Headers)
	}
}

// dsh's pi-ai provider (anthropic-messages / openai-completions) sends
// x-session-affinity, unlike its native deepseek provider which sends
// x-deepseek-harness-session-id. Without this mapping those requests reach
// zen's /go/v1 without x-opencode-session and fail with MissingSessionID.
func TestDshSessionAffinityMapped(t *testing.T) {
	resp := mustIntercept(t, map[string][]string{"X-Session-Affinity": {"ses_affinity_1"}})
	if got := resp.Headers["X-Opencode-Session"]; len(got) != 1 || got[0] != "ses_affinity_1" {
		t.Fatalf("headers = %v", resp.Headers)
	}
}

func TestClientHeaderPreserved(t *testing.T) {
	resp := mustIntercept(t, map[string][]string{
		"Session-Id":        {"s1"},
		"x-opencode-client": {"opencode"},
	})
	if _, ok := resp.Headers["X-Opencode-Client"]; ok {
		t.Fatalf("headers = %v, want client identity preserved", resp.Headers)
	}
	if got := resp.Headers["X-Opencode-Session"]; len(got) != 1 || got[0] != "s1" {
		t.Fatalf("headers = %v", resp.Headers)
	}
}

func TestBlankClientHeaderGetsDefault(t *testing.T) {
	cases := []struct {
		name   string
		values []string
	}{
		{name: "empty list", values: []string{}},
		{name: "blank value", values: []string{"  "}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := mustIntercept(t, map[string][]string{
				"Session-Id":        {"s1"},
				"x-opencode-client": tc.values,
			})
			if got := resp.Headers["X-Opencode-Client"]; len(got) != 1 || got[0] != defaultClientValue {
				t.Fatalf("headers = %v, want default client identity", resp.Headers)
			}
		})
	}
}

// X-Client-Request-Id is a last-resort source: dsh's pi-ai openai-responses
// path stamps the session id there. It ranks below every other source, so a
// real session header always wins when both are present.
func TestClientRequestIDMappedAsLastResort(t *testing.T) {
	resp := mustIntercept(t, map[string][]string{"X-Client-Request-Id": {"req-1"}})
	if got := resp.Headers["X-Opencode-Session"]; len(got) != 1 || got[0] != "req-1" {
		t.Fatalf("headers = %v, want x-opencode-session=req-1", resp.Headers)
	}
}

func TestSessionHeaderBeatsClientRequestID(t *testing.T) {
	resp := mustIntercept(t, map[string][]string{
		"X-Client-Request-Id": {"per-call"},
		"Session-Id":          {"codex-ses-1"},
	})
	if got := resp.Headers["X-Opencode-Session"]; len(got) != 1 || got[0] != "codex-ses-1" {
		t.Fatalf("headers = %v, want the stable session id to win", resp.Headers)
	}
}

// DeepSeek Harness sends no session header at all on its pi-ai transport, so
// nothing is mappable. The host-computed canonical_session_id (present on the
// after-auth pass) supplies the conversation identity instead.
func TestCanonicalSessionFallback(t *testing.T) {
	resp := mustInterceptWithMeta(t,
		map[string][]string{"User-Agent": {"deepseek-harness/0.1.5-rc.1"}},
		map[string]any{"canonical_session_id": "codex:probe-capture-1"})
	if got := resp.Headers["X-Opencode-Session"]; len(got) != 1 || got[0] != "codex:probe-capture-1" {
		t.Fatalf("headers = %v, want fallback session id", resp.Headers)
	}
}

func TestInvalidCanonicalSessionFallbackIgnored(t *testing.T) {
	for _, value := range []string{"contains\nnewline", strings.Repeat("x", maxSessionIDBytes+1)} {
		resp := mustInterceptWithMeta(t,
			map[string][]string{"User-Agent": {"deepseek-harness/0.1.5-rc.1"}},
			map[string]any{"canonical_session_id": value})
		if len(resp.Headers) != 0 {
			t.Fatalf("value %q: headers = %v, want empty", value, resp.Headers)
		}
	}
}

// A client-supplied source must always outrank the fallback, even when both
// are present — the fallback exists only for clients that identify nothing.
func TestClientHeaderBeatsFallback(t *testing.T) {
	resp := mustInterceptWithMeta(t,
		map[string][]string{"Session-Id": {"codex-ses-1"}},
		map[string]any{"canonical_session_id": "codex:should-not-win"})
	if got := resp.Headers["X-Opencode-Session"]; len(got) != 1 || got[0] != "codex-ses-1" {
		t.Fatalf("headers = %v, want client header to win", resp.Headers)
	}
}

func TestNoFallbackWithoutMetadata(t *testing.T) {
	resp := mustIntercept(t, map[string][]string{"User-Agent": {"deepseek-harness/0.1.5-rc.1"}})
	if len(resp.Headers) != 0 {
		t.Fatalf("headers = %v, want empty when no metadata and no source header", resp.Headers)
	}
}

func TestFallbackIgnoresMalformedMetadata(t *testing.T) {
	for _, meta := range []map[string]any{
		{"canonical_session_id": ""},
		{"canonical_session_id": "   "},
		{"canonical_session_id": 42},
		{"canonical_session_id": nil},
		{"other_key": "x"},
	} {
		resp := mustInterceptWithMeta(t, map[string][]string{"User-Agent": {"dsh"}}, meta)
		if len(resp.Headers) != 0 {
			t.Fatalf("meta %v: headers = %v, want empty", meta, resp.Headers)
		}
	}
}

func TestRegister(t *testing.T) {
	out, err := handleMethod("plugin.register", nil)
	if err != nil {
		t.Fatal(err)
	}
	var env envelope
	if err := json.Unmarshal(out, &env); err != nil {
		t.Fatal(err)
	}
	if !env.OK {
		t.Fatalf("register not ok: %s", out)
	}
	var reg registration
	if err := json.Unmarshal(env.Result, &reg); err != nil {
		t.Fatal(err)
	}
	if reg.SchemaVersion != abiVersion {
		t.Fatalf("schema version = %d, want %d", reg.SchemaVersion, abiVersion)
	}
	if !reg.Capabilities.RequestInterceptor {
		t.Fatal("want request_interceptor capability")
	}
	if reg.Metadata.Name != pluginID ||
		reg.Metadata.Version != pluginVersion ||
		reg.Metadata.Author != "ahoo" ||
		reg.Metadata.GitHubRepository != "https://github.com/Lynn-Becky/cpa-plugin-opencode" {
		t.Fatalf("metadata = %+v, want current release identity", reg.Metadata)
	}
}

func TestRequestPayloadSizeAllowed(t *testing.T) {
	for _, size := range []uint64{0, maxRequestPayloadBytes - 1, maxRequestPayloadBytes} {
		if !requestPayloadSizeAllowed(size) {
			t.Fatalf("payload size %d should be accepted", size)
		}
	}
	for _, size := range []uint64{maxRequestPayloadBytes + 1, ^uint64(0)} {
		if requestPayloadSizeAllowed(size) {
			t.Fatalf("payload size %d should be rejected", size)
		}
	}
}

func TestProcessPluginCallReturnsFailureEnvelope(t *testing.T) {
	raw, status := processPluginCall("request.intercept_after", []byte(`{"Headers":`))
	if status != 1 {
		t.Fatalf("status = %d, want 1", status)
	}
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	if env.OK || env.Error == nil || env.Error.Code != "plugin_error" {
		t.Fatalf("envelope = %+v, want plugin_error", env)
	}
}

// Host-shaped envelopes carry the full request body: encoding/json marshals
// []byte as a base64 string (~4/3 expansion), so a 6,378,698-byte body
// serializes past the old 8 MiB gate. The plugin only maps headers/metadata
// through a narrow projection that omits Body, so mapping still succeeds on
// both interceptor methods.
func TestHostShapedLargeBodyPayloadMapped(t *testing.T) {
	const sessionFixture = "123e4567-e89b-12d3-a456-426614174000"
	for _, method := range []string{"request.intercept_before", "request.intercept_after"} {
		raw, err := json.Marshal(struct {
			RequestID string              `json:"RequestID"`
			TraceID   string              `json:"TraceID"`
			Source    string              `json:"SourceFormat"`
			Headers   map[string][]string `json:"Headers"`
			Metadata  map[string]any      `json:"Metadata"`
			Body      []byte              `json:"Body"`
		}{
			RequestID: "large-body",
			TraceID:   "trace",
			Source:    "claude",
			Headers:   map[string][]string{"X-Claude-Code-Session-Id": {sessionFixture}},
			Body:      []byte(strings.Repeat("a", 6378698)),
		})
		if err != nil {
			t.Fatal(err)
		}
		if len(raw) <= 8<<20 {
			t.Fatal("fixture does not exceed the previous payload gate")
		}
		if !requestPayloadSizeAllowed(uint64(len(raw))) {
			t.Fatal("host-shaped envelope rejected by payload gate")
		}
		out, err := handleMethod(method, raw)
		if err != nil {
			t.Fatal(err)
		}
		var env envelope
		if err := json.Unmarshal(out, &env); err != nil {
			t.Fatal(err)
		}
		if !env.OK {
			t.Fatal("host-shaped envelope not accepted")
		}
		var resp interceptResponse
		if err := json.Unmarshal(env.Result, &resp); err != nil {
			t.Fatal(err)
		}
		got := resp.Headers["X-Opencode-Session"]
		if len(got) != 1 || got[0] != sessionFixture {
			t.Fatal("host-shaped envelope session not mapped")
		}
		client := resp.Headers["X-Opencode-Client"]
		if len(client) != 1 || client[0] != defaultClientValue {
			t.Fatal("host-shaped envelope client header not mapped")
		}
	}
}

// A valid 36-byte UUID-shaped client session id maps on both interceptor
// passes; the mapped header carries the client value through unchanged.
func TestClaudeCodeUUIDSessionMappedBothMethods(t *testing.T) {
	const sessionFixture = "123e4567-e89b-12d3-a456-426614174000"
	if len(sessionFixture) != 36 {
		t.Fatal("session fixture must be 36 bytes")
	}
	for _, method := range []string{"request.intercept_before", "request.intercept_after"} {
		raw, err := json.Marshal(interceptRequest{
			RequestID: "uuid-shape",
			Headers:   map[string][]string{"X-Claude-Code-Session-Id": {sessionFixture}},
		})
		if err != nil {
			t.Fatal(err)
		}
		out, err := handleMethod(method, raw)
		if err != nil {
			t.Fatal(err)
		}
		var env envelope
		if err := json.Unmarshal(out, &env); err != nil {
			t.Fatal(err)
		}
		if !env.OK {
			t.Fatal("uuid-shaped session envelope not accepted")
		}
		var resp interceptResponse
		if err := json.Unmarshal(env.Result, &resp); err != nil {
			t.Fatal(err)
		}
		got := resp.Headers["X-Opencode-Session"]
		if len(got) != 1 || got[0] != sessionFixture {
			t.Fatal("uuid-shaped session not mapped")
		}
	}
}

// regenerateRequestID derives one value per host request id so the
// before-auth and after-auth interceptor passes agree on a single wire value,
// and varies it across requests: a fixed id fails the free-tier fingerprint.
func TestRequestIDDeterministicPerRequestAndVaried(t *testing.T) {
	first, err := regenerateRequestID("host-request-1")
	if err != nil {
		t.Fatal(err)
	}
	again, err := regenerateRequestID("host-request-1")
	if err != nil {
		t.Fatal(err)
	}
	if first != again {
		t.Fatalf("derived ids drifted: %q vs %q", first, again)
	}
	other, err := regenerateRequestID("host-request-2")
	if err != nil {
		t.Fatal(err)
	}
	if other == first {
		t.Fatalf("distinct request ids shared %q", first)
	}
	if !requestIDPattern.MatchString(first) {
		t.Fatalf("derived id %q does not match the official format", first)
	}
}

// Without a host request id the value is generated fresh per call; two calls
// must not share an id.
func TestRequestIDRandomWithoutEnvelopeID(t *testing.T) {
	first, err := regenerateRequestID("")
	if err != nil {
		t.Fatal(err)
	}
	second, err := regenerateRequestID("")
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatalf("random ids collided: %q", first)
	}
	if !requestIDPattern.MatchString(first) {
		t.Fatalf("random id %q does not match the official format", first)
	}
}

// The interceptor emits the request id per request: distinct host request ids
// derive distinct values, and an absent host request id degrades to per-call
// generation.
func TestInterceptorRequestIDVariesPerRequest(t *testing.T) {
	idFor := func(t *testing.T, requestID string) string {
		t.Helper()
		raw, err := json.Marshal(interceptRequest{RequestID: requestID, Headers: map[string][]string{"Session-Id": {"s"}}})
		if err != nil {
			t.Fatal(err)
		}
		out, err := handleMethod("request.intercept_before", raw)
		if err != nil {
			t.Fatal(err)
		}
		var env envelope
		if err := json.Unmarshal(out, &env); err != nil {
			t.Fatal(err)
		}
		if !env.OK {
			t.Fatalf("envelope not ok: %s", out)
		}
		var resp interceptResponse
		if err := json.Unmarshal(env.Result, &resp); err != nil {
			t.Fatal(err)
		}
		return mustMatchingRequestID(t, resp.Headers)
	}
	first := idFor(t, "host-request-a")
	second := idFor(t, "host-request-b")
	if first == second {
		t.Fatalf("distinct host request ids derived %q twice", first)
	}
	third := idFor(t, "")
	fourth := idFor(t, "")
	if third == fourth {
		t.Fatalf("generated ids collided on %q", third)
	}
}

// A client-supplied x-opencode-request passes through unchanged (never
// replaced with a generated one), but a conflicting case-variant pair fails
// closed instead of forwarding arbitrary garbage.
func TestClientRequestHeaderPreservedAndConflictFailsClosed(t *testing.T) {
	resp := mustIntercept(t, map[string][]string{
		"Session-Id":         {"s1"},
		"x-opencode-request": {"msg_fromclient00000000000"},
	})
	if got := resp.Headers["X-Opencode-Request"]; len(got) != 1 || got[0] != "msg_fromclient00000000000" {
		t.Fatalf("headers = %v, want the client value preserved", resp.Headers)
	}
	if got := resp.Headers["X-Opencode-Session"]; len(got) != 1 || got[0] != "s1" {
		t.Fatalf("headers = %v, want s1 mapped anyway", resp.Headers)
	}
	resp = mustIntercept(t, map[string][]string{
		"Session-Id":         {"s1"},
		"X-Opencode-Request": {"msg_aaaaaaaaaaaaaa"},
		"x-opencode-request": {"msg_bbbbbbbbbbbbbbbbbbbb"},
	})
	if len(resp.Headers) != 0 {
		t.Fatalf("headers = %v, want empty for conflicting request headers", resp.Headers)
	}
}

// x-opencode-project mirrors the official CLI: injected as "global" when
// absent, preserved when present, fail-closed on conflicting pairs.
func TestProjectHeaderBehavior(t *testing.T) {
	resp := mustIntercept(t, map[string][]string{"Session-Id": {"s1"}})
	if got := resp.Headers["X-Opencode-Project"]; len(got) != 1 || got[0] != defaultProjectValue {
		t.Fatalf("headers = %v, want global", resp.Headers)
	}
	resp = mustIntercept(t, map[string][]string{
		"Session-Id":         {"s1"},
		"x-opencode-project": {"personal"},
	})
	if got := resp.Headers["X-Opencode-Project"]; len(got) != 1 || got[0] != "personal" {
		t.Fatalf("headers = %v, want the client value preserved", resp.Headers)
	}
	resp = mustIntercept(t, map[string][]string{
		"Session-Id":         {"s1"},
		"X-Opencode-Project": {"a"},
		"x-opencode-project": {"b"},
	})
	if len(resp.Headers) != 0 {
		t.Fatalf("headers = %v, want empty for conflicting project headers", resp.Headers)
	}
}

// The session-id mirror: injected beside a mapped session, preserved when the
// client sent its own, fail-closed when the client's values conflict.
func TestSessionIDMirrorBehavior(t *testing.T) {
	resp := mustIntercept(t, map[string][]string{"Session-Id": {"s1"}})
	if got := resp.Headers["X-Opencode-Session-Id"]; len(got) != 1 || got[0] != "s1" {
		t.Fatalf("headers = %v, want the s1 mirror", resp.Headers)
	}
	resp = mustIntercept(t, map[string][]string{
		"Session-Id":            {"s1"},
		"X-Opencode-Session-Id": {"client-own"},
	})
	if got := resp.Headers["X-Opencode-Session-Id"]; len(got) != 1 || got[0] != "client-own" {
		t.Fatalf("headers = %v, want the client value preserved", resp.Headers)
	}
	resp = mustIntercept(t, map[string][]string{
		"Session-Id":            {"s1"},
		"X-Opencode-Session-Id": {"a"},
		"x-opencode-session-id": {"b"},
	})
	if len(resp.Headers) != 0 {
		t.Fatalf("headers = %v, want empty for conflicting session-id headers", resp.Headers)
	}
}

// A conflicting x-opencode-session presented directly by the client (poisoned
// authoritative source) still fails closed as a whole.
func TestPoisonedAuthoritativeSessionFailsClosed(t *testing.T) {
	resp := mustIntercept(t, map[string][]string{
		"X-Opencode-Session":    {"a"},
		"x-opencode-session-id": {"b"},
		"x-opencode-session":    {"c"},
	})
	if len(resp.Headers) != 0 {
		t.Fatalf("headers = %v, want empty", resp.Headers)
	}
}
