package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha3"
	"crypto/x509"
	"embed"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"hash"
	"html"
	"io/fs"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"uuid"

	"github.com/luikyv/go-oidc/pkg/goidc"
	"github.com/luikyv/go-oidc/pkg/provider"
	xmpp "gosrc.io/xmpp"
	"gosrc.io/xmpp/stanza"
)

const (
	httpAuthNS  = "http://jabber.org/protocol/http-auth" // XEP-0070
	vcard4NS    = "urn:ietf:params:xml:ns:vcard-4.0"     // RFC 6351
	nickNode    = "http://jabber.org/protocol/nick"
	vcard4Node  = "urn:xmpp:vcard4"
	pepTimeout  = 5 * time.Second
	confirmWait = 120 * time.Second
	maxPending  = 128
)

//go:embed static
var staticFS embed.FS

type confirm struct {
	XMLName xml.Name `xml:"http://jabber.org/protocol/http-auth confirm"`
	ID      string   `xml:"id,attr"`
	Method  string   `xml:"method,attr"`
	URL     string   `xml:"url,attr"`
}

func init() {
	stanza.TypeRegistry.MapExtension(stanza.PKTMessage,
		xml.Name{Space: httpAuthNS, Local: "confirm"}, confirm{})
}

const txnAlphabet = "23456789abcdefghjkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ"

var txnUpper = big.NewInt(int64(len(txnAlphabet)))

func newTransactionCode() (string, error) {
	s := make([]byte, 9)
	for i := range s {
		n, err := rand.Int(rand.Reader, txnUpper)
		if err != nil {
			return "", err
		}
		s[i] = txnAlphabet[n.Int64()]
	}
	return string(s), nil
}

func dcrPolicy(_ context.Context, id string, meta *goidc.ClientMeta) error {
	if len(meta.RedirectURIs) > maxRedirectURIs {
		return fmt.Errorf("at most %d redirect_uris", maxRedirectURIs)
	}
	for _, raw := range meta.RedirectURIs {
		if err := validateRedirectURI(raw); err != nil {
			return err
		}
	}
	if raw, ok := meta.CustomAttributes["scopes"]; ok {
		parts := []string{}
		if arr, ok := raw.([]any); ok {
			for _, s := range arr {
				if str, ok := s.(string); ok {
					parts = append(parts, str)
				}
			}
		}
		meta.ScopeIDs = strings.Join(parts, " ")
		delete(meta.CustomAttributes, "scopes")
	}
	// Public clients only
	meta.TokenAuthnMethod = goidc.AuthnMethodNone
	if len(meta.GrantTypes) == 0 {
		meta.GrantTypes = []goidc.GrantType{goidc.GrantAuthorizationCode}
	}
	if len(meta.ResponseTypes) == 0 {
		meta.ResponseTypes = []goidc.ResponseType{goidc.ResponseTypeCode}
	}
	if len(meta.Name) > 100 {
		meta.Name = meta.Name[:100]
	}
	return nil
}

func validateRedirectURI(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || strings.ContainsRune(raw, ' ') {
		return fmt.Errorf("invalid redirect_uri %q", raw)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return errors.New("redirect_uri scheme must be http or https")
	}
	// http allowed only for loopback origins
	host := u.Hostname()
	loopback := host == "localhost" || host == "127.0.0.1" || host == "::1"
	if u.Scheme == "http" && !loopback {
		return errors.New("non-loopback redirect_uri must be https")
	}
	return nil
}

func runComponent(comp *xmpp.Component, dead <-chan error) {
	backoff := time.Second
	for {
		if err := comp.Connect(); err != nil {
			log.Printf("component connect: %v (retry in %s)", err, backoff)
			time.Sleep(backoff)
			if backoff < 60*time.Second {
				backoff *= 2
			}
			continue
		}
		log.Printf("component connected (domain %s)", comp.Domain)
		backoff = time.Second
		log.Printf("component dropped: %v", <-dead)
	}
}

func loadSigningKey(path string) (*rsa.PrivateKey, error) {
	if b, err := os.ReadFile(path); err == nil {
		k, err := x509.ParsePKCS8PrivateKey(b)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
		rsaKey, ok := k.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("stored key is not RSA")
		}
		return rsaKey, nil
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	if dir := filepath.Dir(path); dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, err
		}
	}
	if err := os.WriteFile(path, der, 0o600); err != nil {
		return nil, err
	}
	log.Printf("wrote new signing key to %s", path)
	return key, nil
}

type jtiLedger struct {
	mu     sync.Mutex
	seen   map[string]time.Time
	maxAge time.Duration
}

func newJTILedger(maxAge time.Duration) *jtiLedger {
	l := &jtiLedger{seen: make(map[string]time.Time), maxAge: maxAge}
	go l.sweep()
	return l
}

func (l *jtiLedger) consume(_ context.Context, jti string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, dup := l.seen[jti]; dup {
		return fmt.Errorf("replayed jti %s", jti)
	}
	l.seen[jti] = time.Now()
	return nil
}

func (l *jtiLedger) sweep() {
	t := time.NewTicker(time.Minute)
	for range t.C {
		now := time.Now()
		l.mu.Lock()
		for jti, ts := range l.seen {
			if now.Sub(ts) > l.maxAge {
				delete(l.seen, jti)
			}
		}
		l.mu.Unlock()
	}
}

type confirmationResult struct {
	approved bool
	err      string
}

type pendingConfirmation struct {
	deadline time.Time
	bare     string
	txn      string
	confirm  *confirmationResult
	vcard    map[string]any
	nick     *string
}

type confirmBroker struct {
	mu   sync.Mutex
	pend map[string]*pendingConfirmation
	conn *xmpp.Component
}

func newConfirmBroker() *confirmBroker {
	return &confirmBroker{pend: make(map[string]*pendingConfirmation)}
}

func (b *confirmBroker) Ask(thread, jid, txn, method, requestedURL string) (int, map[string]any, string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	pc := b.pend[thread]

	// Already asked, check status
	if pc != nil {
		if pc.confirm != nil && pc.vcard != nil && pc.nick != nil {
			delete(b.pend, thread)
			if pc.confirm.err != "" {
				return 0, nil, "", errors.New(pc.confirm.err)
			}
			if pc.confirm.approved {
				return 1, pc.vcard, *pc.nick, nil
			}
			return 0, nil, "", nil
		} else if time.Now().After(pc.deadline) {
			delete(b.pend, thread)
			return 0, nil, "", fmt.Errorf("no answer within %v", confirmWait)
		} else {
			return -1, nil, "", nil // Still waiting
		}
	}

	now := time.Now()
	for key, pc := range b.pend {
		// If we're twice past the timeout, remove any data
		if now.After(pc.deadline.Add(confirmWait)) {
			delete(b.pend, key)
		}
	}

	if len(b.pend) >= maxPending {
		return 0, nil, "", fmt.Errorf("busy, try again")
	}
	pc = &pendingConfirmation{bare: bareJID(jid), txn: txn, deadline: time.Now().Add(confirmWait)}
	b.pend[thread] = pc

	body := fmt.Sprintf("A web login is being requested for %s.\n%s\nTransaction identifier: %s\n"+
		"If this was you, reply with \"OK\" to confirm (or \"No\" to cancel).",
		jid, requestedURL, txn)

	ext := confirm{ID: txn, Method: method, URL: requestedURL}

	msg := stanza.Message{
		Attrs: stanza.Attrs{
			To:   jid,
			Type: stanza.MessageTypeNormal,
			Id:   thread,
		},
		Body:       body,
		Thread:     thread,
		Extensions: []stanza.MsgExtension{&ext},
	}

	if err := b.conn.Send(msg); err != nil {
		return 0, nil, "", fmt.Errorf("component not connected or send failed: %w", err)
	}
	log.Printf("login requested: jid=%s txn=%s", jid, txn)

	go func() {
		vc, err := fetchVCard4(context.Background(), b.conn, jid)
		b.mu.Lock()
		defer b.mu.Unlock()
		if err != nil {
			log.Printf("vcard4 lookup for %s: %v", jid, err)
		} else {
			pc.vcard = vc
		}
		if pc.vcard == nil {
			pc.vcard = map[string]any{}
		}
	}()

	go func() {
		nick, err := fetchNicknamePEP(context.Background(), b.conn, jid)
		b.mu.Lock()
		defer b.mu.Unlock()
		pc.nick = &nick
		if err != nil {
			log.Printf("nickname lookup for %s: %v", jid, err)
		}
	}()

	return -1, nil, "", nil
}

func (b *confirmBroker) onMessage(_ xmpp.Sender, p stanza.Packet) {
	msg, ok := p.(stanza.Message)
	if !ok || msg.From == "" {
		return
	}
	from := bareJID(msg.From)

	b.mu.Lock()
	defer b.mu.Unlock()
	var (
		key       string
		pc        *pendingConfirmation
		res       confirmationResult
		found     bool
		ambiguous bool
		ambigTxns []string
	)
	if msg.Thread != "" {
		if cand, isKnown := b.pend[msg.Thread]; !isKnown || cand.bare != from {
			// Unknown thread, or reply from the wrong JID
		} else {
			key, pc, found = msg.Thread, cand, true
			if res, ok = structuredAnswer(msg, cand.txn); ok {
				// typed XEP-0070 reply
			} else if approved, _, ok := parsePlainAnswer(msg.Body); ok {
				res = confirmationResult{approved, ""}
			} else {
				found = false
			}
		}
	} else {
		approved, txn, plain := parsePlainAnswer(msg.Body)
		if !plain {
			return
		}
		var exact string
		var keys []string
		for k, cand := range b.pend {
			if cand.bare != from {
				continue
			}
			if txn != "" {
				if cand.txn == txn { // "OK 1a2b3c…"
					exact = k
				}
			} else {
				keys = append(keys, k)
			}
		}
		switch {
		case exact != "":
			key = exact
		case len(keys) == 1:
			key = keys[0]
		case len(keys) > 1:
			ambiguous = true
			for _, k := range keys {
				ambigTxns = append(ambigTxns, b.pend[k].txn)
			}
		}
		if key != "" {
			pc, found = b.pend[key], true
			res = confirmationResult{approved, ""}
		}
	}

	switch {
	case found:
		pc.confirm = &res
		log.Printf("login answer: jid=%s txn=%s approved=%v", msg.From, pc.txn, res.approved)
	case ambiguous:
		body := "Several logins are pending. Repeat your answer with the transaction " +
			"identifier from the relevant message, e.g. \"OK " + ambigTxns[0] + "\". " +
			"Pending: " + strings.Join(ambigTxns, ", ")
		err := b.conn.Send(stanza.Message{
			Attrs: stanza.Attrs{To: msg.From, Type: stanza.MessageTypeNormal},
			Body:  body,
		})
		log.Printf("login ambiguous: jid=%s multiple pending, nudge %v", from, err)
	}
}

func structuredAnswer(msg stanza.Message, txn string) (confirmationResult, bool) {
	for _, ext := range msg.Extensions {
		if c, ok := ext.(*confirm); ok && c.ID == txn {
			return confirmationResult{approved: msg.Type != "error", err: msg.Error.Text}, true
		}
	}
	return confirmationResult{}, false
}

func parsePlainAnswer(body string) (approved bool, txn string, understood bool) {
	fields := strings.Fields(strings.TrimSpace(body))
	if len(fields) == 0 || len(fields) > 2 {
		return false, "", false
	}
	switch strings.ToLower(fields[0]) {
	case "ok", "yes":
		approved = true
	case "no":
	default:
		return false, "", false
	}
	txnid := ""
	if len(fields) > 1 {
		txnid = fields[1]
	}
	return approved, txnid, true
}

func fetchPEPItem(ctx context.Context, conn *xmpp.Component, bare, node string) (*stanza.Node, error) {
	ctx, cancel := context.WithTimeout(ctx, pepTimeout)
	defer cancel()

	iq, err := stanza.NewItemsRequest(bare, node, 1)
	if err != nil {
		return nil, fmt.Errorf("build %s request: %w", node, err)
	}
	iq.Id = uuid.NewV4().String()

	ch, err := conn.SendIQ(ctx, iq)
	if err != nil {
		return nil, fmt.Errorf("%s query: %w", node, err)
	}

	select {
	case res := <-ch:
		if res.Type == stanza.IQTypeError {
			return nil, nil
		}
		ps, ok := res.Payload.(*stanza.PubSubGeneric)
		if !ok {
			return nil, fmt.Errorf("unexpected payload %T", res.Payload)
		}
		if ps.Items == nil || len(ps.Items.List) == 0 {
			return nil, nil
		}
		return ps.Items.List[0].Any, nil
	case <-ctx.Done():
		go func() {
			select {
			case <-ch:
			case <-time.After(time.Minute):
			}
		}()
		return nil, ctx.Err()
	}
}

func fetchNicknamePEP(ctx context.Context, conn *xmpp.Component, bare string) (string, error) {
	n, err := fetchPEPItem(ctx, conn, bare, nickNode)
	if err != nil || n == nil || n.XMLName.Space != nickNode {
		return "", err
	}
	return strings.TrimSpace(n.Content), nil
}

func fetchVCard4(ctx context.Context, conn *xmpp.Component, bare string) (map[string]any, error) {
	n, err := fetchPEPItem(ctx, conn, bare, vcard4Node)
	if err != nil || n == nil || n.XMLName.Local != "vcard" || n.XMLName.Space != vcard4NS {
		return nil, err
	}
	return vcard4Claims(n), nil
}

func vcard4Claims(v *stanza.Node) map[string]any {
	claims := map[string]any{}

	setStr(claims, "name", kid(nodeChild(v, "fn"), "text"))

	if n := nodeChild(v, "n"); n != nil {
		setStr(claims, "family_name", strings.Join(kids(n, "surname"), " "))
		setStr(claims, "given_name", strings.Join(kids(n, "given"), " "))
		setStr(claims, "middle_name", strings.Join(kids(n, "additional"), " "))
	}

	setStr(claims, "nickname", kid(nodeChild(v, "nickname"), "text"))
	setStr(claims, "picture", kid(nodeChild(v, "photo"), "uri"))
	setStr(claims, "website", kid(nodeChild(v, "url"), "uri"))
	setStr(claims, "zoneinfo", kid(nodeChild(v, "tz"), "text"))
	setStr(claims, "locale", kid(nodeChild(v, "lang"), "language-tag"))

	if d := kid(nodeChild(v, "bday"), "date"); len(d) == 8 {
		if t, err := time.Parse("20060102", d); err == nil {
			claims["birthdate"] = t.Format("2006-01-02")
		}
	}

	setStr(claims, "email", kid(nodeChild(v, "email"), "text"))

	return claims
}

func nodeChild(n *stanza.Node, local string) *stanza.Node {
	if n == nil {
		return nil
	}
	for i := range n.Nodes {
		if n.Nodes[i].XMLName.Local == local {
			return &n.Nodes[i]
		}
	}
	return nil
}

func kid(n *stanza.Node, local string) string {
	if n == nil {
		return ""
	}
	for i := range n.Nodes {
		if n.Nodes[i].XMLName.Local == local {
			if s := strings.TrimSpace(n.Nodes[i].Content); s != "" {
				return s
			}
		}
	}
	return ""
}

func kids(n *stanza.Node, local string) []string {
	if n == nil {
		return nil
	}
	var out []string
	for i := range n.Nodes {
		if n.Nodes[i].XMLName.Local == local {
			if s := strings.TrimSpace(n.Nodes[i].Content); s != "" {
				out = append(out, s)
			}
		}
	}
	return out
}

func setStr(m map[string]any, key, val string) {
	if val = strings.TrimSpace(val); val != "" {
		m[key] = val
	}
}

func normalizeJID(in string) (bare, full string, err error) {
	in = strings.TrimSpace(in)
	local, domain, ok := strings.Cut(in, "@")
	if !ok || local == "" || domain == "" {
		return "", "", fmt.Errorf("invalid JID")
	}
	host, resource := domain, ""
	if h, r, ok := strings.Cut(domain, "/"); ok {
		host, resource = h, r
	}
	if host == "" ||
		strings.ContainsAny(local, "@/ \t") ||
		strings.ContainsAny(host, "/@ \t") ||
		strings.ContainsAny(resource, "/ \t") {
		return "", "", fmt.Errorf("invalid JID")
	}
	local, host = strings.ToLower(local), strings.ToLower(host)
	bare = local + "@" + host
	if resource != "" {
		full = bare + "/" + resource
	} else {
		full = bare
	}
	return bare, full, nil
}

func bareJID(full string) string {
	if i := strings.IndexByte(full, '/'); i >= 0 {
		full = full[:i]
	}
	return strings.ToLower(full)
}

const (
	maxLocalpartOctets = 64 // RFC 5321 limit on the local-part
	upperHex           = "0123456789ABCDEF"
)

// emailLocalpartByte marks bytes that may appear verbatim in an unquoted email
// local-part (the RFC 5321 "atext" set), except:
//   - '=', reserved as the escape introducer; and
//   - '.', which RFC 5321 allows only between atext characters, so it is
//     handled positionally by validDotString.
var emailLocalpartByte = func() (t [256]bool) {
	for _, c := range "!#$%&'*+-/?^_`{|}~" {
		t[byte(c)] = true
	}
	for c := '0'; c <= '9'; c++ {
		t[byte(c)] = true
	}
	for c := 'A'; c <= 'Z'; c++ {
		t[byte(c)] = true
	}
	for c := 'a'; c <= 'z'; c++ {
		t[byte(c)] = true
	}
	return
}()

func encodeEmailLocalpart(s string, keepDots bool) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if emailLocalpartByte[c] || (keepDots && c == '.') {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('=')
		b.WriteByte(upperHex[c>>4])
		b.WriteByte(upperHex[c&0x0f])
	}
	return b.String()
}

func validDotString(s string) bool {
	return s != "" && s[0] != '.' && s[len(s)-1] != '.' && !strings.Contains(s, "..")
}

func emailForJID(bare, gateway string) (string, error) {
	local := encodeEmailLocalpart(bare, true)
	// '.' may pass through, but RFC 5321 forbids it at the edges and doubled,
	// so fall back to escaping dots as well.
	if !validDotString(local) {
		local = encodeEmailLocalpart(bare, false)
	}
	if len(local) > maxLocalpartOctets {
		return "", fmt.Errorf("encoded local-part is %d octets, over the %d limit",
			len(local), maxLocalpartOctets)
	}
	return local + "@" + gateway, nil
}

func parseCredentials(r *http.Request) (jid, txn string, ok bool) {
	if jid := strings.TrimSpace(r.PostFormValue("jid")); jid != "" {
		txn = strings.TrimSpace(r.PostFormValue("txn"))
		return jid, txn, txn != ""
	}
	return
}

func hasScope(scopes, want string) bool {
	for _, s := range strings.Fields(scopes) {
		if s == want {
			return true
		}
	}
	return false
}

const pollPage = `<!DOCTYPE html>
<html><head><meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<meta http-equiv="refresh" content="1" />
<title>Sign in with Jabber ID</title>
<link rel="stylesheet" href="/static/simple.css" />
</head><body>
<h1>Sign in with Jabber ID</h1>
<p class="notice">Please check your app for a prompt with the transaction ID
<strong>%[1]s</strong>.</p>
<small>If this page does not reload after you have approved the login using
your app, you can reload it manually.</small>
</body></html>`

func xmpp70AuthnPolicy(broker *confirmBroker) goidc.AuthnPolicy {
	return goidc.NewPolicy("xep-0070",
		func(*http.Request, *goidc.AuthnSession, *goidc.Client) bool { return true },
		func(w http.ResponseWriter, r *http.Request, as *goidc.AuthnSession, client *goidc.Client) (goidc.Status, error) {
			redir := redirectForDisplay(as, client)
			profileRequested := hasScope(as.Scopes, "profile") || hasScope(as.Scopes, "email")
			if as.Store == nil {
				as.Store = map[string]any{}
			}
			jid, txn, have := parseCredentials(r)
			if have {
				as.Store["jid"] = jid
				as.Store["txn"] = txn
				as.Store["shareProfile"] = profileRequested && r.PostFormValue("share_profile") != ""
			} else {
				jid, _ = as.Store["jid"].(string)
				txn, _ = as.Store["txn"].(string)
				if jid == "" || txn == "" {
					writeLoginPage(w, as.ID, redir, "", profileRequested)
					return goidc.StatusPending, nil
				}
			}
			bare, full, err := normalizeJID(jid)
			if err != nil {
				writeLoginPage(w, as.ID, redir, "That Jabber ID isn't valid", profileRequested)
				return goidc.StatusPending, nil
			}
			shareProfile := as.Store["shareProfile"].(bool)
			app, vcard, nick, err := broker.Ask(as.ID, bare, txn, "GET", redir)
			switch {
			case err != nil:
				writeLoginPage(w, as.ID, redir, err.Error(), profileRequested)
				return goidc.StatusPending, nil
			case app == 0:
				writeLoginPage(w, as.ID, redir, "Request was denied", profileRequested)
				return goidc.StatusPending, nil
			case app == -1:
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				w.Header().Set("Cache-Control", "no-store")
				fmt.Fprintf(w, pollPage, txn)
				return goidc.StatusPending, nil
			}
			sub := hmac.New(func() hash.Hash { return sha3.New256() }, []byte(os.Getenv("SALT")+as.ClientID))
			sub.Write([]byte(bare))
			as.Subject = hex.EncodeToString(sub.Sum(nil))
			if shareProfile {
				as.GrantedScopes = as.Scopes
				for k, val := range vcard {
					as.Store[k] = val
				}
				if nick != "" {
					as.Store["nickname"] = nick
				}
				local, _, _ := strings.Cut(bare, "@")
				as.Username = local
			} else {
				as.GrantedScopes = "openid"
			}
			log.Printf("authenticated: %s (client %s)", full, as.ClientID)
			return goidc.StatusSuccess, nil
		})
}

func redirectForDisplay(as *goidc.AuthnSession, client *goidc.Client) string {
	if u := strings.TrimSpace(as.RedirectURI); u != "" {
		return u
	}
	if client != nil && len(client.ClientMeta.RedirectURIs) > 0 {
		return client.ClientMeta.RedirectURIs[0]
	}
	return ""
}

const loginPage = `<!DOCTYPE html>
<html><head><meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Sign in with Jabber ID</title>
<link rel="stylesheet" href="/static/simple.css" />
</head><body>
<h1>Sign in with Jabber ID</h1>
<p>Login sends a confirmation to your Jabber ID. Approve it in your app. </p>
<p>You'll be redirected to <code>%[4]s</code> after login.</p>
<form method="post" action="/authorize/%[1]s">
 <label>Jabber ID
  <input name="jid" placeholder="you@example.com" required autofocus></label>
 <label>Transaction code <input type="text" name="txn" value="%[3]s"><br />
<small>Will be shown in your app, and must match.</small></label>
 %[5]s
 %[2]s
 <button type="submit">Login</button>
</form>
</body></html>`

func writeLoginPage(w http.ResponseWriter, sessionID, redirectURL, errMsg string, profileRequested bool) {
	code, err := newTransactionCode()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if redirectURL == "" {
		redirectURL = "the application you were using"
	}
	notice := ""
	if errMsg != "" {
		notice = "<p class='notice'>" + html.EscapeString(errMsg) + "</p>"
	}
	consent := ""
	if profileRequested {
		consent = `<label>Share profile information
				<input type="checkbox" name="share_profile" checked />
			</label>`
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, loginPage, html.EscapeString(url.PathEscape(sessionID)), notice,
		html.EscapeString(code), html.EscapeString(redirectURL), consent)
}

var corsEndpoints = map[string]string{
	"/token":    "POST, OPTIONS",
	"/userinfo": "GET, POST, OPTIONS",
}

func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		allow, ok := corsEndpoints[r.URL.Path]
		if !ok {
			next.ServeHTTP(w, r)
			return
		}
		h := w.Header()
		h.Set("Access-Control-Allow-Origin", "*")
		h.Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		if r.Method == http.MethodOptions {
			h.Set("Access-Control-Allow-Methods", allow)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func listenOn(addr string) (net.Listener, error) {
	path, isUnix := strings.CutPrefix(addr, "unix:")
	if !isUnix {
		return net.Listen("tcp", addr)
	}

	if fi, err := os.Stat(path); err == nil {
		if fi.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("%s exists and is not a socket", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, fmt.Errorf("remove stale socket %s: %w", path, err)
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}

	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if strings.HasPrefix(path, "@") {
		return ln, nil
	}
	if err := os.Chmod(path, 0o666); err != nil {
		ln.Close()
		return nil, fmt.Errorf("chmod %s: %w", path, err)
	}
	return ln, nil
}

func main() {
	iss := envOr("ISSUER", "http://localhost:8080")
	listen := envOr("LISTEN", ":8080")

	keyPath := envOr("JWKS_KEY", "jwks.key")
	key, err := loadSigningKey(keyPath)
	if err != nil {
		log.Fatal(err)
	}

	emailGateway := os.Getenv("EMAIL_GATEWAY")
	if emailGateway != "" {
		log.Printf("email claims will be minted at %s", emailGateway)
	}

	jwks := goidc.JSONWebKeySet{Keys: []goidc.JSONWebKey{{
		KeyID:     "oidc1",
		Key:       key,
		Algorithm: string(goidc.SigAlgRS256),
		Use:       string(goidc.KeyUsageSignature),
	}}}

	broker := newConfirmBroker()
	router := xmpp.NewRouter()
	router.HandleFunc("message", broker.onMessage)

	compErr := make(chan error, 1)
	comp, err := xmpp.NewComponent(xmpp.ComponentOptions{
		TransportConfiguration: xmpp.TransportConfiguration{
			Address: envOr("XMPP_SERVER", "localhost:5347"),
			Domain:  os.Getenv("XMPP_DOMAIN"),
		},
		Domain:   os.Getenv("XMPP_DOMAIN"),
		Secret:   os.Getenv("XMPP_COMPONENT_SECRET"),
		Name:     "OIDC sign-in (XEP-0070)",
		Category: "gateway",
		Type:     "proxy",
		EventManager: xmpp.EventManager{
			Handler: func(e xmpp.Event) error {
				log.Printf("component event: %v", e)
				return nil
			},
		},
	}, router, func(err error) {
		log.Printf("component: %v", err)
		select {
		case compErr <- err:
		default:
		}
	})
	if err != nil {
		log.Fatal(err)
	}
	broker.conn = comp
	go runComponent(comp, compErr)

	dcrDB, err := newSQLiteDCRManager(envOr("DB", "xmpp-oidc.sqlite"))
	if err != nil {
		log.Fatal(err)
	}

	jti := newJTILedger(10 * time.Minute)
	var profileStoreKeys = []string{
		"nickname",
		"name", "given_name", "family_name", "middle_name",
		"picture", "website", "birthdate", "zoneinfo", "locale",
	}

	op, err := provider.New(
		provider.Config{
			Issuer:      iss,
			JWKS:        func(context.Context) (goidc.JSONWebKeySet, error) { return jwks, nil },
			IDTokenAlgs: []goidc.SignatureAlgorithm{goidc.SigAlgRS256},
			// default in-memory store
		},
		provider.WithScopes(goidc.ScopeOpenID, goidc.ScopeProfile, goidc.ScopeEmail),
		provider.WithOpenIDScopeRequired(),
		provider.WithClaims(
			"preferred_username", "jid",
			"name", "given_name", "family_name", "middle_name", "nickname",
			"picture", "website", "birthdate", "zoneinfo", "locale",
			"email", "email_verified",
		),
		provider.WithUserInfoClaims(func(_ context.Context, grant *goidc.Grant) map[string]any {
			claims := map[string]any{}
			if hasScope(grant.Scopes, "profile") {
				claims["preferred_username"] = grant.Username
				claims["jid"] = grant.Store["jid"]
				for _, k := range profileStoreKeys {
					if v, ok := grant.Store[k]; ok && v != nil && v != "" {
						claims[k] = v
					}
				}
			}
			if hasScope(grant.Scopes, "email") {
				jid, _ := grant.Store["jid"].(string)
				if emailGateway != "" {
					if addr, err := emailForJID(jid, emailGateway); err == nil {
						claims["email"] = addr
						claims["email_verified"] = true
					} else {
						log.Printf("no email claim for %s: %v", jid, err)
					}
				} else if addr, _ := grant.Store["email"].(string); addr != "" {
					claims["email"] = addr
					claims["email_verified"] = false
				}
			}
			return claims
		}),
		provider.WithAuthSessionLifetime(300),
		provider.WithNoneAuthn(), // public clients only. PKCE required
		provider.WithDCR(
			dcrDB,
			provider.WithDCRClientHandler(dcrPolicy),
		),
		provider.WithAuthCodeGrant(
			provider.AuthCodeGrantConfig{
				ResponseTypes: []goidc.ResponseType{goidc.ResponseTypeCode},
			},
			provider.WithAuthPolicies(xmpp70AuthnPolicy(broker)),
			provider.WithPKCE([]goidc.CodeChallengeMethod{goidc.CodeChallengeMethodSHA256},
				provider.WithPKCERequired()),
			provider.WithAuthCodeLifetime(60),
			provider.WithFormPostResponseMode(),
		),
		provider.WithJTIConsumer(jti.consume),
	)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("discovery: %s/.well-known/openid-configuration", iss)

	if _, err := staticFS.ReadFile("static/simple.css"); err != nil {
		log.Fatalf("embedded asset missing: %v", err)
	}

	mux := http.NewServeMux()
	staticSub, err := fs.Sub(staticFS, "static")
	if err != nil {
		log.Fatal(err)
	}
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServerFS(staticSub)))

	op.RegisterRoutes(mux)

	ln, err := listenOn(listen)
	if err != nil {
		log.Fatalf("listen on %s: %v", listen, err)
	}
	srv := &http.Server{
		Handler:     withCORS(mux),
		ReadTimeout: 5 * time.Second,
	}
	log.Printf("OIDC endpoints + static assets on %s", ln.Addr())
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
