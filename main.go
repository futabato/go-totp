package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/skip2/go-qrcode"
)

const (
	stepSeconds      = int64(30)
	digits           = 6
	validationWindow = 1
)

var (
	b32Encoding = base32.StdEncoding.WithPadding(base32.NoPadding)
	indexTmpl   = template.Must(template.New("index").Parse(`
<!doctype html>
<html lang="ja">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Go TOTP 2FA Prototype</title>
  <style>
    body { font-family: sans-serif; margin: 2rem; max-width: 760px; line-height: 1.6; }
    h1 { margin-bottom: 0.2rem; }
    code, pre { background: #f5f5f5; padding: 0.2rem 0.4rem; border-radius: 4px; }
    pre { white-space: pre-wrap; word-break: break-all; }
    .box { border: 1px solid #ddd; border-radius: 8px; padding: 1rem; margin-top: 1rem; }
    .status { padding: 0.8rem; border-radius: 8px; background: #eef6ff; border: 1px solid #cde4ff; }
    input { padding: 0.4rem; font-size: 1rem; }
    button { padding: 0.45rem 0.8rem; font-size: 1rem; cursor: pointer; }
    .qr { border: 1px solid #ddd; border-radius: 6px; width: 220px; height: 220px; }
  </style>
</head>
<body>
  <h1>Go + Google Authenticator 2FA</h1>
  <p>TOTP (RFC 6238, SHA1, 30秒, 6桁) の学習用プロトタイプです。</p>

  {{if .Status}}
  <p class="status">{{.Status}}</p>
  {{end}}

  <div class="box">
    <h2>1. シークレット発行</h2>
    <form action="/enroll" method="post">
      <label>Account名:
        <input name="account" value="{{.Account}}" placeholder="example@example.com">
      </label>
      <button type="submit">新しいシークレットを発行</button>
    </form>
  </div>

  {{if .Enrolled}}
  <div class="box">
    <h2>2. Google Authenticatorに登録</h2>
    <p>Google Authenticatorで「+」→「QRコードをスキャン」で読み取ってください。</p>
    <p><img class="qr" src="/qr" alt="TOTP setup QR code"></p>
    <p>読み取れない場合は「セットアップキーを入力」を選び、以下を設定してください。</p>
    <p><strong>アカウント名:</strong> {{.Account}}</p>
    <p><strong>キー:</strong> <code>{{.SecretBase32}}</code></p>
    <p><strong>タイプ:</strong> 時間ベース</p>
    <p><strong>Issuer:</strong> {{.Issuer}}</p>
    <p>対応する <code>otpauth://</code> URI:</p>
    <pre>{{.OtpauthURI}}</pre>
  </div>

  <div class="box">
    <h2>3. ワンタイムコード検証</h2>
    <form action="/verify" method="post">
      <label>6桁コード:
        <input name="code" inputmode="numeric" pattern="[0-9]{6}" placeholder="123456" maxlength="6">
      </label>
      <button type="submit">検証する</button>
    </form>
    <p>時刻ずれ許容: 前後1ステップ (±30秒)</p>
  </div>
  {{end}}
</body>
</html>
`))
)

type server struct {
	mu         sync.RWMutex
	issuer     string
	account    string
	secret     []byte
	secretB32  string
	lastStatus string
}

type pageData struct {
	Issuer       string
	Account      string
	SecretBase32 string
	OtpauthURI   string
	Status       string
	Enrolled     bool
}

func main() {
	s := &server{
		issuer:  "GoTOTPPrototype",
		account: "demo@example.com",
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/enroll", s.handleEnroll)
	mux.HandleFunc("/qr", s.handleQR)
	mux.HandleFunc("/verify", s.handleVerify)

	addr := ":8080"
	log.Printf("listening on http://localhost%s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatal(err)
	}
}

func (s *server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.mu.RLock()
	data := pageData{
		Issuer:       s.issuer,
		Account:      s.account,
		SecretBase32: s.secretB32,
		OtpauthURI:   buildOtpauthURI(s.issuer, s.account, s.secretB32),
		Status:       s.lastStatus,
		Enrolled:     len(s.secret) > 0,
	}
	s.mu.RUnlock()

	if err := indexTmpl.Execute(w, data); err != nil {
		http.Error(w, "template error", http.StatusInternalServerError)
	}
}

func (s *server) handleEnroll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	account := strings.TrimSpace(r.FormValue("account"))
	if account == "" {
		account = "demo@example.com"
	}

	secretRaw, secretB32, err := generateSecret()
	if err != nil {
		http.Error(w, "failed to generate secret", http.StatusInternalServerError)
		return
	}

	s.mu.Lock()
	s.account = account
	s.secret = secretRaw
	s.secretB32 = secretB32
	s.lastStatus = "新しいシークレットを発行しました。Google Authenticatorに登録してください。"
	s.mu.Unlock()

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *server) handleVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	code := strings.TrimSpace(r.FormValue("code"))
	code = strings.ReplaceAll(code, " ", "")

	s.mu.RLock()
	secret := append([]byte(nil), s.secret...)
	s.mu.RUnlock()

	if len(secret) == 0 {
		s.setStatus("先にシークレットを発行してください。")
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	if verifyTOTP(secret, code, time.Now().UTC(), stepSeconds, digits, validationWindow) {
		s.setStatus("検証成功: コードは有効です。")
	} else {
		s.setStatus("検証失敗: コードが無効か、時刻がずれています。")
	}

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *server) handleQR(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.mu.RLock()
	hasSecret := len(s.secret) > 0
	issuer := s.issuer
	account := s.account
	secretB32 := s.secretB32
	s.mu.RUnlock()

	if !hasSecret || secretB32 == "" {
		http.Error(w, "no enrolled secret", http.StatusNotFound)
		return
	}

	otpauthURI := buildOtpauthURI(issuer, account, secretB32)
	png, err := qrcode.Encode(otpauthURI, qrcode.Medium, 256)
	if err != nil {
		http.Error(w, "failed to generate qr", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "no-store")
	if _, err := w.Write(png); err != nil {
		log.Printf("failed to write qr: %v", err)
	}
}

func (s *server) setStatus(msg string) {
	s.mu.Lock()
	s.lastStatus = msg
	s.mu.Unlock()
}

func generateSecret() ([]byte, string, error) {
	raw := make([]byte, 20)
	if _, err := rand.Read(raw); err != nil {
		return nil, "", err
	}
	return raw, b32Encoding.EncodeToString(raw), nil
}

func verifyTOTP(secret []byte, code string, now time.Time, step int64, digits int, window int) bool {
	if len(code) != digits {
		return false
	}
	for _, ch := range code {
		if ch < '0' || ch > '9' {
			return false
		}
	}

	counter := now.Unix() / step
	for offset := -window; offset <= window; offset++ {
		c := counter + int64(offset)
		if c < 0 {
			continue
		}
		if generateTOTP(secret, c, digits) == code {
			return true
		}
	}
	return false
}

func generateTOTP(secret []byte, counter int64, digits int) string {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(counter))

	mac := hmac.New(sha1.New, secret)
	mac.Write(buf[:])
	hash := mac.Sum(nil)

	offset := int(hash[len(hash)-1] & 0x0f)
	truncated := (int(hash[offset])&0x7f)<<24 |
		(int(hash[offset+1])&0xff)<<16 |
		(int(hash[offset+2])&0xff)<<8 |
		(int(hash[offset+3]) & 0xff)

	otp := truncated % pow10(digits)
	return fmt.Sprintf("%0*d", digits, otp)
}

func pow10(n int) int {
	v := 1
	for i := 0; i < n; i++ {
		v *= 10
	}
	return v
}

func buildOtpauthURI(issuer, account, secretB32 string) string {
	label := url.PathEscape(issuer + ":" + account)
	q := url.Values{}
	q.Set("secret", secretB32)
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", strconv.Itoa(digits))
	q.Set("period", strconv.FormatInt(stepSeconds, 10))
	return "otpauth://totp/" + label + "?" + q.Encode()
}
