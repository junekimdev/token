package token

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"strings"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
)

// Constants
const (
	TokenIssuer           string = "github.com/JuneKimDev/token"
	TokenSubjectDelimiter string = "#"
)

// Errors
var (
	ErrNoFilepath         = errors.New("Filepath is empty")
	ErrPrvKeyNotInitiated = errors.New("Private key is not initiated")
	ErrPubKeyNotInitiated = errors.New("Public key is not initiated")
	ErrInvalidToken       = errors.New("Token is invalid")
)

// Keys
var (
	prvKey *rsa.PrivateKey
	pubKey interface{}
)

// InitPrvKey initializes private key
func InitPrvKey(filepath string) error {
	key, err := getPrivateKey(filepath)
	if err != nil {
		return err
	}
	prvKey = key
	return nil
}

// InitPubKey initializes public key
func InitPubKey(filepath string) error {
	key, err := getPublicKey(filepath)
	if err != nil {
		return err
	}
	pubKey = key
	return nil
}

func getKeyPem(filepath string) (*pem.Block, error) {
	if filepath == "" {
		return nil, ErrNoFilepath
	}
	keyFile, err := ioutil.ReadFile(filepath)
	if err != nil {
		return nil, err
	}
	keyPem, _ := pem.Decode(keyFile)
	return keyPem, nil
}

// getPrivateKey getter
func getPrivateKey(filepath string) (*rsa.PrivateKey, error) {
	keyPem, err := getKeyPem(filepath)
	if err != nil {
		return nil, err
	}
	return x509.ParsePKCS1PrivateKey(keyPem.Bytes)
}

// getPublicKey getter
func getPublicKey(filepath string) (interface{}, error) {
	keyPem, err := getKeyPem(filepath)
	if err != nil {
		return nil, err
	}
	return x509.ParsePKCS1PublicKey(keyPem.Bytes)
}

// Create outputs JWT signed token string, expiration timestamp, and errors
//
// "expIn" is a string as in time.ParseDuration: e.g. 1h, 10m, 1.5s, -300ms, 1h20m
func Create(sub, aud, expIn string) (string, int64, error) {
	// Check private key
	if prvKey == nil {
		return "", 0, ErrPrvKeyNotInitiated
	}

	// Get Expiration time
	tDelta, err := time.ParseDuration(expIn)
	if err != nil {
		return "", 0, err
	}

	// Create claims
	now := time.Now()
	expAt := now.Add(tDelta).Unix()
	claims := jwt.StandardClaims{
		Audience:  aud,
		ExpiresAt: expAt,
		Id:        uuid.New().String(),
		IssuedAt:  now.Unix(),
		Issuer:    TokenIssuer,
		NotBefore: now.Unix(),
		Subject:   sub,
	}

	// Create a token with RS256 algorithm signing method
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	// Sign the token with the key
	signedToken, err := token.SignedString(prvKey)
	if err != nil {
		return "", 0, err
	}

	return signedToken, expAt, nil
}

// Verify parses/verifies JWT and returns subject
func Verify(tokenString string, aud string) (sub string, err error) {
	// Check public key
	if pubKey == nil {
		return "", ErrPubKeyNotInitiated
	}

	// Parse the token string
	token, err := jwt.ParseWithClaims(tokenString, &jwt.StandardClaims{}, func(token *jwt.Token) (interface{}, error) {
		return pubKey, nil
	})
	if err != nil {
		return "", ErrInvalidToken
	}

	// Extract claims
	claims := token.Claims.(*jwt.StandardClaims)
	sub = claims.Subject

	// Verify claims
	if err != nil || !claims.VerifyAudience(aud, true) || !claims.VerifyIssuer(TokenIssuer, true) {
		return sub, ErrInvalidToken
	}
	return sub, nil
}

// GetSubject returns properly formatted subject that perme micro-services can understand
func GetSubject(userID, deviceID string) string {
	return userID + TokenSubjectDelimiter + deviceID
}

// ParseSubject parses subject and returns user id and device id
func ParseSubject(sub string) (userID, deviceID string) {
	subs := strings.Split(sub, TokenSubjectDelimiter)
	return subs[0], subs[1]
}
