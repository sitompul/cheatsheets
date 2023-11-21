package cheatsheets

import (
	"bytes"
	cryptoRand "crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/rand"
	"net/mail"
	"strconv"
	"strings"
	"time"
	"unicode"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/net/html"
	"golang.org/x/text/unicode/norm"
)

var SKIP = []*unicode.RangeTable{
	unicode.Mark,
	unicode.Sk,
	unicode.Lm,
}

var SAFE = []*unicode.RangeTable{
	unicode.Letter,
	unicode.Number,
}

// Slugify a string. The result will only contain lowercase letters,
// digits and dashes. It will not begin or end with a dash, and it
// will not contain runs of multiple dashes.
//
// It is NOT forced into being ASCII, but may contain any Unicode
// characters, with the above restrictions.
func Slugify(text string) string {
	buf := make([]rune, 0, len(text))
	dash := false
	for _, r := range norm.NFKD.String(text) {
		switch {
		case unicode.IsOneOf(SAFE, r):
			buf = append(buf, unicode.ToLower(r))
			dash = true
		case unicode.IsOneOf(SKIP, r):
		case dash:
			buf = append(buf, '-')
			dash = false
		}
	}
	if i := len(buf) - 1; i >= 0 && buf[i] == '-' {
		buf = buf[:i]
	}
	return string(buf)
}

// SanitizeEmail remove dots from gmail addresses.
func SanitizeEmail(email string) string {
	if !IsEmail(email) {
		return ""
	}

	result := email
	if strings.HasSuffix(result, "@gmail.com") {
		address := strings.Split(result, "@")
		if len(address) != 2 {
			return ""
		}
		user := strings.ReplaceAll(address[0], ".", "")
		result = user + "@gmail.com"
	}
	return strings.ToLower(result)
}

// HashPassword : Convert string to bcrypt hash.
func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

// CheckPasswordHash : Check if hash and password are a pair.
func CheckPasswordHash(password, hash string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

// IsEmail checks if the email is correct.
func IsEmail(email string) bool {
	_, err := mail.ParseAddress(email)
	return err == nil
}

// Token : generate 6 digit token for validation and lost password.
func Token() string {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	min := 10000
	max := 999999

	random := r.Intn(max-min+1) + min

	otp := strconv.Itoa(random)
	if len(otp) < 6 {
		otp = "0" + otp
	}
	return otp
}

// IsNilString checks if string is either null reference or empty valued string.
func IsNilString(input *string) bool {
	return input == nil || *input == ""
}

func InclStr(slice []string, text string) bool {
	for _, val := range slice {
		if val == text {
			return true
		}
	}
	return false
}

// IntersectStr returns intersect of two string slices.
func IntersectStr(first []string, second []string) []string {
	m := make(map[string]string)
	for _, i := range first {
		m[i] = i
	}

	temp := make(map[string]string)
	for _, i := range second {
		if _, ok := m[i]; ok {
			temp[i] = i
		}
	}
	keys := make([]string, 0, len(temp))
	for k := range temp {
		keys = append(keys, k)
	}
	return keys
}

func APIKeyDecode(apikey string) (name string, secret string, err error) {
	errAPIKey := errors.New("not a valid apikey")
	hash := strings.Split(apikey, ".")
	if len(hash) != 2 {
		return "", "", errAPIKey
	}
	nameByte, err := base64.StdEncoding.DecodeString(hash[0])
	if err != nil {
		return "", "", errAPIKey
	}
	secretByte, err := base64.StdEncoding.DecodeString(hash[1])
	if err != nil {
		return "", "", errAPIKey
	}
	name = string(nameByte)
	secret = string(secretByte)
	return
}

func NilStr(input *string) bool {
	if input == nil {
		return true
	}
	return *input == ""
}

// removeElements deletes all dangerous element that will send attack to user inbox.
func removeElements(n *html.Node) {
	// if note is script tag
	if n.Type == html.ElementNode && n.Data == "script" {
		n.Parent.RemoveChild(n)
		return
	}
	// traverse DOM
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		defer removeElements(c)
	}
}

func SanitizeHTML(input string) (string, error) {
	doc, err := html.Parse(strings.NewReader(input))
	if err != nil {
		return "", err
	}
	var content bytes.Buffer
	removeElements(doc)
	html.Render(&content, doc)
	return content.String(), nil
}

func convertKeyToPEM(key interface{}) (string, error) {
	var keyType string
	var derBytes []byte

	switch key := key.(type) {
	case *rsa.PrivateKey:
		keyType = "RSA PRIVATE KEY"
		derBytes = x509.MarshalPKCS1PrivateKey(key)
	case *rsa.PublicKey:
		keyType = "RSA PUBLIC KEY"
		derBytes, err := x509.MarshalPKIXPublicKey(key)
		if err != nil {
			return "", err
		}
		return string(pem.EncodeToMemory(&pem.Block{Type: keyType, Bytes: derBytes})), nil
	default:
		return "", fmt.Errorf("unsupported key type")
	}

	return string(pem.EncodeToMemory(&pem.Block{Type: keyType, Bytes: derBytes})), nil
}

// GenerateAesPair : generate public and private key.
func GenerateAesPair() (private string, public string, err error) {
	privateKey, err := rsa.GenerateKey(cryptoRand.Reader, 2048)
	if err != nil {
		return "", "", err
	}

	publicKey := &privateKey.PublicKey
	privateKeyStr, err := convertKeyToPEM(publicKey)
	if err != nil {
		return "", "", err
	}

	publicKeyStr, err := convertKeyToPEM(publicKey)
	if err != nil {
		return "", "", err
	}

	return privateKeyStr, publicKeyStr, nil
}

// Convert from string version of private key to the private key struct.
func LoadPrivateKeyFromPEM(privateKeyStr string) (*rsa.PrivateKey, error) {
	privateKeyPEM := []byte(privateKeyStr)
	block, _ := pem.Decode(privateKeyPEM)
	if block == nil {
		return nil, errors.New("failed to decode PEM")
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

// Convert from string version of private key to the public key struct.
func LoadPublicKeyFromPEM(publicKeyStr string) (*rsa.PublicKey, error) {
	publicKeyPEM := []byte(publicKeyStr)
	block, _ := pem.Decode(publicKeyPEM)
	if block == nil {
		return nil, errors.New("failed to decode PEM")
	}
	return x509.ParsePKCS1PublicKey(block.Bytes)
}

func EncryptAes(content string, public string) (string, error) {
	pubKey, err := LoadPublicKeyFromPEM(public)
	if err != nil {
		return "", err
	}
	ciphertext, err := rsa.EncryptPKCS1v15(cryptoRand.Reader, pubKey, []byte(content))
	if err != nil {
		return "", err
	}
	return string(ciphertext), nil
}

// DecryptAes : convert ciphered text into decoded content.
func DecryptAes(cipher string, private string) (string, error) {
	privKey, err := LoadPrivateKeyFromPEM(private)
	if err != nil {
		return "", err
	}
	content, err := privKey.Decrypt(cryptoRand.Reader, []byte(cipher), &rsa.OAEPOptions{
		Hash: 0,
	})
	if err != nil {
		return "", err
	}
	return string(content), nil
}
