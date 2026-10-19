package main

/*
#include <stdint.h>
#include <stdlib.h>

typedef struct {
	void* ptr;
	size_t len;
} cliproxy_buffer;

typedef int (*cliproxy_host_call_fn)(void*, const char*, const uint8_t*, size_t, cliproxy_buffer*);
typedef void (*cliproxy_host_free_fn)(void*, size_t);

typedef struct {
	uint32_t abi_version;
	void* host_ctx;
	cliproxy_host_call_fn call;
	cliproxy_host_free_fn free_buffer;
} cliproxy_host_api;

typedef int (*cliproxy_plugin_call_fn)(char*, uint8_t*, size_t, cliproxy_buffer*);
typedef void (*cliproxy_plugin_free_fn)(void*, size_t);
typedef void (*cliproxy_plugin_shutdown_fn)(void);

typedef struct {
	uint32_t abi_version;
	cliproxy_plugin_call_fn call;
	cliproxy_plugin_free_fn free_buffer;
	cliproxy_plugin_shutdown_fn shutdown;
} cliproxy_plugin_api;

extern int cliproxyPluginCall(char*, uint8_t*, size_t, cliproxy_buffer*);
extern void cliproxyPluginFree(void*, size_t);
extern void cliproxyPluginShutdown(void);

static const cliproxy_host_api* stored_host;

static void store_host_api(const cliproxy_host_api* host) {
	stored_host = host;
}
*/
import "C"

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"unicode"
	"unsafe"
)

const abiVersion uint32 = 1

const (
	pluginID = "opencode-session-mapper"

	// maxRequestPayloadBytes caps the serialized native interceptor envelope.
	// Fixed and non-configurable. The host serializes the whole
	// RequestInterceptRequest as JSON, including Body ([]byte marshals as a
	// base64 string at roughly 4/3 of the raw body), so legitimate
	// Host-shaped payloads carrying multi-megabyte bodies exceed 8 MiB on the
	// wire. This plugin only maps headers and metadata, so interceptRequest
	// keeps a narrow JSON projection that omits Body (the decoder scans but
	// does not base64-decode or retain unknown fields) - but the envelope gate
	// must still admit the full 64 MiB. The check runs before any pointer
	// dereference, before any allocation, and before the C.size_t -> C.int
	// conversion feeding C.GoBytes, keeping that conversion bounded
	// (64 MiB is far below 2 GiB).
	maxRequestPayloadBytes = 64 << 20
	maxSessionIDBytes      = 1024

	targetSessionHeader   = "X-Opencode-Session"
	targetSessionIDHeader = "X-Opencode-Session-Id"
	targetRequestHeader   = "X-Opencode-Request"
	targetClientHeader    = "X-Opencode-Client"
	targetProjectHeader   = "X-Opencode-Project"

	// Wire fingerprint of the official OpenCode CLI (free-tier snapshot,
	// 2026-10-19). Upstream rejects free-tier requests whose custom headers
	// do not look like the official client (403 FreeTierError):
	//   - x-opencode-client: "cli" (a proxy self-label such as "cliproxy"
	//     no longer passes)
	//   - x-opencode-project: "global"
	//   - x-opencode-request: "msg_" + 12 hex + 14 base62, varied per request
	//   - x-opencode-session / x-opencode-session-id: a REAL session the
	//     official CLI minted (fabricated ids are rejected outright)
	// The plugin injects these (never overriding client-provided ones); the
	// User-Agent must be pinned per zen credential in config.yml.
	defaultClientValue  = "cli"
	defaultProjectValue = "global"

	requestIDPrefix   = "msg_"
	requestIDHexLen   = 12
	requestIDAlphaLen = 14

	hexDigits   = "0123456789abcdef"
	alphaDigits = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
)

var pluginVersion = "0.4.0"

// sessionSources lists downstream client headers that carry a stable
// per-conversation session id, in priority order. The first non-empty
// value wins and is forwarded as x-opencode-session (OpenCode Zen uses
// it for sticky routing / prompt-cache affinity; since 09/06 requests
// without it may error).
//
// Deliberately EXCLUDED:
//   - Conversation_id: set by the server itself, not the client.
var sessionSources = []string{
	"Session-Id",                    // codex CLI (also matches session_id case-insensitively? no: see below)
	"Session_id",                    // codex CLI underscore variant (EqualFold misses _ vs -)
	"Thread-Id",                     // codex CLI thread = conversation
	"Thread_id",                     // underscore variant
	"X-Claude-Code-Session-Id",      // claude code
	"X-DeepSeek-Harness-Session-Id", // dsh / deepseek-harness native provider
	"X-Session-Affinity",            // dsh pi-ai (anthropic-messages, openai-completions)
	"X-Session-Id",                  // generic (opencode-ish clients, aicoding-proxy default)
	// Last resort: dsh's pi-ai openai-responses path stamps the session id here
	// (pi-ai sends it alongside x-session-affinity/x-session-id, which those
	// clients may not use). Ranked last because other tools set it per call.
	"X-Client-Request-Id",
}

type envelope struct {
	OK     bool            `json:"ok"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  *envelopeError  `json:"error,omitempty"`
}

type envelopeError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type registration struct {
	SchemaVersion uint32       `json:"schema_version"`
	Metadata      metadata     `json:"metadata"`
	Capabilities  capabilities `json:"capabilities"`
}

type metadata struct {
	Name             string `json:"Name"`
	Version          string `json:"Version"`
	Author           string `json:"Author"`
	GitHubRepository string `json:"GitHubRepository"`
	Logo             string `json:"Logo"`
	ConfigFields     []any  `json:"ConfigFields"`
}

type capabilities struct {
	RequestInterceptor bool `json:"request_interceptor"`
}

// interceptRequest is a narrow projection of the host's
// RequestInterceptRequest envelope. Body is intentionally absent: the host
// may attach the full request body (base64-encoded by encoding/json), and
// the plugin never needs it - only headers and metadata are mapped. The JSON
// decoder scans unknown fields but does not base64-decode or retain Body.
type interceptRequest struct {
	RequestID string              `json:"RequestID"`
	Headers   map[string][]string `json:"Headers"`
	// Metadata carries host-computed request facts. Populated only on the
	// after-auth pass (request.intercept_after), where it includes
	// canonical_session_id — see sessionFallback.
	Metadata map[string]any `json:"Metadata"`
}

type interceptResponse struct {
	Headers      map[string][]string `json:"Headers"`
	ClearHeaders []string            `json:"ClearHeaders"`
}

func main() {}

//export cliproxy_plugin_init
func cliproxy_plugin_init(host *C.cliproxy_host_api, plugin *C.cliproxy_plugin_api) C.int {
	if plugin == nil {
		return 1
	}
	C.store_host_api(host)
	plugin.abi_version = C.uint32_t(abiVersion)
	plugin.call = C.cliproxy_plugin_call_fn(C.cliproxyPluginCall)
	plugin.free_buffer = C.cliproxy_plugin_free_fn(C.cliproxyPluginFree)
	plugin.shutdown = C.cliproxy_plugin_shutdown_fn(C.cliproxyPluginShutdown)
	return 0
}

//export cliproxyPluginCall
func cliproxyPluginCall(method *C.char, request *C.uint8_t, requestLen C.size_t, response *C.cliproxy_buffer) (status C.int) {
	status = 1
	if response == nil {
		return 1
	}
	response.ptr = nil
	response.len = 0
	defer func() {
		if recover() != nil {
			writeResponse(response, errorEnvelope("plugin_panic", "plugin call failed"))
			status = 1
		}
	}()
	if method == nil {
		writeResponse(response, errorEnvelope("invalid_method", "method is required"))
		return 1
	}
	// Envelope gate first: reject oversized input before any pointer
	// dereference, before any allocation, and before narrowing C.size_t to
	// C.int for C.GoBytes.
	if !requestPayloadSizeAllowed(uint64(requestLen)) {
		writeResponse(response, errorEnvelope("invalid_request", "request payload exceeds size limit"))
		return 1
	}
	var payload []byte
	if requestLen > 0 {
		if request == nil {
			writeResponse(response, errorEnvelope("invalid_request", "request buffer is required"))
			return 1
		}
		payload = C.GoBytes(unsafe.Pointer(request), C.int(requestLen))
	}
	raw, callStatus := processPluginCall(C.GoString(method), payload)
	writeResponse(response, raw)
	return C.int(callStatus)
}

func processPluginCall(method string, payload []byte) ([]byte, int) {
	raw, errHandle := handleMethod(method, payload)
	if errHandle != nil {
		return errorEnvelope("plugin_error", errHandle.Error()), 1
	}
	return raw, 0
}

//export cliproxyPluginFree
func cliproxyPluginFree(ptr unsafe.Pointer, len C.size_t) {
	if ptr != nil {
		C.free(ptr)
	}
	_ = len
}

//export cliproxyPluginShutdown
func cliproxyPluginShutdown() {}

func handleMethod(method string, payload []byte) ([]byte, error) {
	switch method {
	case "plugin.register", "plugin.reconfigure":
		return okEnvelopeJSON(registration{
			SchemaVersion: abiVersion,
			Metadata: metadata{
				Name:             pluginID,
				Version:          pluginVersion,
				Author:           "ahoo",
				GitHubRepository: "https://github.com/Lynn-Becky/cpa-plugin-opencode",
				Logo:             "",
				ConfigFields:     []any{},
			},
			Capabilities: capabilities{RequestInterceptor: true},
		})
	case "request.intercept_before", "request.intercept_after":
		return interceptHeaders(payload)
	default:
		return errorEnvelope("unknown_method", "unknown method: "+method), nil
	}
}

func requestPayloadSizeAllowed(size uint64) bool {
	return size <= maxRequestPayloadBytes
}

// Header lookup outcomes. headerConflict marks a header that matched but
// whose values are unusable (empty list, control characters, oversized, or
// conflicting repeated / case-variant values); callers fail closed instead
// of selecting a value using randomized map iteration order.
const (
	headerOK = iota
	headerAbsent
	headerConflict
)

// lookupHeader matches name case-insensitively and returns the first value
// with ok == headerOK when every matched value normalizes to the same
// identifier. Empty lists, invalid values, or conflicting values are reported
// as headerConflict with an empty value.
func lookupHeader(headers map[string][]string, name string) (string, int) {
	matched := false
	selected := ""
	for key, values := range headers {
		if !strings.EqualFold(key, name) {
			continue
		}
		matched = true
		if len(values) == 0 {
			return "", headerConflict
		}
		for _, raw := range values {
			value, valid := normalizeSessionID(raw)
			if !valid {
				return "", headerConflict
			}
			if selected == "" {
				selected = value
				continue
			}
			if selected != value {
				return "", headerConflict
			}
		}
	}
	if !matched {
		return "", headerAbsent
	}
	return selected, headerOK
}

// headerValue keeps the historical (value, present) shape used when scanning
// downstream session source headers: a present-but-conflicting header counts
// as present with an empty value so callers can fail closed.
func headerValue(headers map[string][]string, name string) (string, bool) {
	value, status := lookupHeader(headers, name)
	if status == headerOK {
		return value, true
	}
	if status == headerConflict {
		return "", true
	}
	return "", false
}

func headerHasValue(headers map[string][]string, name string) bool {
	for key, values := range headers {
		if !strings.EqualFold(key, name) {
			continue
		}
		for _, value := range values {
			if strings.TrimSpace(value) != "" {
				return true
			}
		}
	}
	return false
}

func normalizeSessionID(value string) (string, bool) {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > maxSessionIDBytes {
		return "", false
	}
	for _, char := range value {
		if unicode.IsControl(char) {
			return "", false
		}
	}
	return value, true
}

func interceptHeaders(payload []byte) ([]byte, error) {
	empty, errEmpty := okEnvelopeJSON(interceptResponse{Headers: map[string][]string{}})
	if errEmpty != nil {
		return nil, errEmpty
	}
	var req interceptRequest
	if len(payload) > 0 {
		if errDecode := json.Unmarshal(payload, &req); errDecode != nil {
			return nil, errDecode
		}
	}
	if req.Headers == nil {
		return empty, nil
	}

	// Session resolution (unchanged rules): a client-sent x-opencode-session
	// (e.g. real opencode CLI) is authoritative and never overridden.
	value, status := lookupHeader(req.Headers, targetSessionHeader)
	if status == headerConflict {
		return empty, nil
	}
	session := value
	if session == "" {
		for _, src := range sessionSources {
			if v, exists := headerValue(req.Headers, src); exists {
				if v == "" {
					return empty, nil
				}
				session = v
				break
			}
		}
		if session == "" {
			session = sessionFallback(req.Metadata)
		}
	}
	if session == "" {
		return empty, nil
	}

	out := map[string][]string{}

	// Map the stable conversation identity, plus the session-id mirror the
	// official CLI sends alongside it. A client-supplied value is echoed
	// unchanged (normalized), never replaced.
	if value == "" {
		out[targetSessionHeader] = []string{session}
	}
	if mirror, mirrorStatus := lookupHeader(req.Headers, targetSessionIDHeader); mirrorStatus == headerConflict {
		return empty, nil
	} else if mirrorStatus == headerAbsent {
		out[targetSessionIDHeader] = []string{session}
	} else {
		out[targetSessionIDHeader] = []string{mirror}
	}

	// Per-request id, matching the official CLI format
	// ("msg_" + 12 hex + 14 base62). Derived from the host request id so
	// both interceptor passes agree on one value; generated when the host
	// provides none. Client-supplied values pass through unchanged.
	// Echoing supplies the value to the `$` header forwarding config;
	// generation failures omit the header: a stale value would fail the
	// free-tier fingerprint.
	if requestID, requestIDStatus := lookupHeader(req.Headers, targetRequestHeader); requestIDStatus == headerConflict {
		return empty, nil
	} else if requestIDStatus == headerAbsent {
		if generated, errRequestID := regenerateRequestID(req.RequestID); errRequestID == nil {
			out[targetRequestHeader] = []string{generated}
		}
	} else {
		out[targetRequestHeader] = []string{requestID}
	}

	// Identify the client as the official CLI when it did not identify itself.
	if !headerHasValue(req.Headers, targetClientHeader) {
		out[targetClientHeader] = []string{defaultClientValue}
	}

	// Official CLI project scope; a client-supplied value passes through.
	if project, projectStatus := lookupHeader(req.Headers, targetProjectHeader); projectStatus == headerConflict {
		return empty, nil
	} else if projectStatus == headerAbsent {
		out[targetProjectHeader] = []string{defaultProjectValue}
	} else {
		out[targetProjectHeader] = []string{project}
	}

	if len(out) == 0 {
		return empty, nil
	}
	return okEnvelopeJSON(interceptResponse{Headers: out})
}

// regenerateRequestID produces one x-opencode-request value per request:
// "msg_" + 12 hex + 14 base62 (official CLI wire format). When the host
// envelope carries a RequestID the value is derived from it, keeping the
// before-auth and after-auth interceptor passes consistent; otherwise it is
// generated fresh via crypto/rand. A fixed value across requests would fail
// the free-tier fingerprint check.
func regenerateRequestID(envelopeRequestID string) (string, error) {
	if envelopeRequestID == "" {
		return randomRequestID()
	}
	digest := sha256.Sum256([]byte(envelopeRequestID))
	var builder strings.Builder
	builder.Grow(len(requestIDPrefix) + requestIDHexLen + requestIDAlphaLen)
	builder.WriteString(requestIDPrefix)
	builder.WriteString(hex.EncodeToString(digest[:requestIDHexLen/2]))
	for _, byteValue := range digest[requestIDHexLen/2 : requestIDHexLen/2+requestIDAlphaLen] {
		builder.WriteByte(alphaDigits[int(byteValue)%62])
	}
	return builder.String(), nil
}

func randomRequestID() (string, error) {
	buf := make([]byte, requestIDHexLen+requestIDAlphaLen)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	var builder strings.Builder
	builder.Grow(len(requestIDPrefix) + len(buf))
	builder.WriteString(requestIDPrefix)
	for _, byteValue := range buf[:requestIDHexLen] {
		builder.WriteByte(hexDigits[int(byteValue)%len(hexDigits)])
	}
	for _, byteValue := range buf[requestIDHexLen:] {
		builder.WriteByte(alphaDigits[int(byteValue)%len(alphaDigits)])
	}
	return builder.String(), nil
}

// sessionFallback returns the host-computed conversation identity for clients
// that send no session header of their own (notably DeepSeek Harness, whose
// pi-ai transport gates session headers behind a switch its adapter withholds —
// so the wire carries nothing to map).
//
// canonical_session_id is built by the core from the source protocol and the
// client's own session id, yielding e.g. "claude:<uuid>" or "codex:<id>". It is
// populated only on the after-auth pass, which is why this is a fallback and
// not a source: a request that already carries a recognized header still wins
// on the before-auth pass, unchanged.
//
// Only consulted when every client-supplied source was absent, so a client
// that does identify itself is never overridden. derived_session_id and
// lcp_affinity_session_id are deliberately NOT used: the former is absent from
// this payload on v7.2.157, and core documents the latter as unusable for
// provider conversation identity.
func sessionFallback(metadata map[string]any) string {
	if metadata == nil {
		return ""
	}
	v, ok := metadata["canonical_session_id"]
	if !ok {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		return ""
	}
	value, valid := normalizeSessionID(s)
	if !valid {
		return ""
	}
	return value
}

func okEnvelopeJSON(result any) ([]byte, error) {
	raw, errMarshal := json.Marshal(result)
	if errMarshal != nil {
		return nil, errMarshal
	}
	return json.Marshal(envelope{OK: true, Result: json.RawMessage(raw)})
}

func errorEnvelope(code, message string) []byte {
	raw, _ := json.Marshal(envelope{OK: false, Error: &envelopeError{Code: code, Message: message}})
	return raw
}

func writeResponse(response *C.cliproxy_buffer, raw []byte) {
	if response == nil || len(raw) == 0 {
		return
	}
	ptr := C.CBytes(raw)
	if ptr == nil {
		return
	}
	response.ptr = ptr
	response.len = C.size_t(len(raw))
}
