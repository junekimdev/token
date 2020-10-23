package token

import (
	"log"
	"testing"
	"time"
)

func testSetup(t *testing.T) func() {
	t.Log("Set Up")
	InitPrvKey("rsa_prv.key")
	InitPubKey("rsa_pub.key")
	return func() {
		t.Log("Tear Down")
		prvKey = nil
		pubKey = nil
	}
}

func TestInitPrvKeyTrue(t *testing.T) {
	if err := InitPrvKey("rsa_prv.key"); err != nil {
		t.Error(err)
	}
}

func TestInitPrvKeyFalse(t *testing.T) {
	if err := InitPrvKey(""); err == nil {
		t.Error("want error but got nil")
	} else {
		log.Println(err)
	}
}

func TestInitPubKeyTrue(t *testing.T) {
	if err := InitPubKey("rsa_pub.key"); err != nil {
		t.Error(err)
	}
}

func TestInitPubKeyFalse(t *testing.T) {
	if err := InitPubKey(""); err == nil {
		t.Error("want error but got nil")
	} else {
		log.Println(err)
	}
}

func TestGetPrivateKeyTrue(t *testing.T) {
	key, err := getPrivateKey("rsa_prv.key")
	if err != nil {
		t.Errorf("Error occurred while getting a private key: %v", err)
	}

	if valid := key.Validate(); valid != nil {
		t.Errorf("Private Key is invalid: %v", valid)
	}
}

func TestGetPrivateKeyFalse(t *testing.T) {
	_, err := getPrivateKey("")
	if err == nil {
		t.Error("want error but got nil")
	} else {
		log.Println(err)
	}
}

func TestGetPublicKeyTrue(t *testing.T) {
	_, err := getPublicKey("rsa_pub.key")
	if err != nil {
		t.Errorf("Error occurred while getting a public key: %v", err)
	}
}

func TestGetPublicKeyFalse(t *testing.T) {
	_, err := getPublicKey("")
	if err == nil {
		t.Error("want error but got nil")
	} else {
		log.Println(err)
	}
}

func TestCreateToken(t *testing.T) {
	teardown := testSetup(t)
	defer teardown()

	sub := GetSubject("127.0.0.1", "clientId")
	aud := "jwt.perme.iam.test"
	expIn := "1h"
	_, err := CreateToken(sub, aud, expIn)
	if err != nil {
		t.Errorf("Failed to create Token: %v", err)
	}
}

func TestCreateTokenBeforeInit(t *testing.T) {
	sub := GetSubject("127.0.0.1", "clientId")
	aud := "jwt.perme.iam.test"
	expIn := "1h"
	_, err := CreateToken(sub, aud, expIn)
	if err == nil {
		t.Error("want error but got nothing")
	} else {
		log.Println(err)
	}
}

func TestVerifyTokenTrue(t *testing.T) {
	teardown := testSetup(t)
	defer teardown()

	subIP := "127.0.0.1"
	subID := "clientId"

	sub := GetSubject(subIP, subID)
	aud := "jwt.perme.iam.test"
	expIn := "1h"
	tokenString, _ := CreateToken(sub, aud, expIn)
	s, err := VerifyToken(tokenString, aud)
	if err != nil {
		t.Errorf("want true but got false: %v", err)
	} else {
		log.Printf("Token subjected to: %s\n", s)
	}
	ip, id := ParseSubject(s)
	if ip != subIP {
		t.Error("Failed to parse subject")
	}
	if id != subID {
		t.Error("Failed to parse subject")
	}
}

func TestVerifyTokenFalse(t *testing.T) {
	teardown := testSetup(t)
	defer teardown()

	sub := GetSubject("127.0.0.1", "clientId")
	aud := "jwt.perme.iam.test"
	expIn := "1h"
	tokenString, _ := CreateToken(sub, aud, expIn)

	if _, err := VerifyToken(tokenString+"1", aud); err == nil {
		t.Errorf("Modified token string-want false but got true: %v", err)
	} else {
		log.Println(err)
	}
	if _, err := VerifyToken(tokenString, aud+"1"); err == nil {
		t.Errorf("Wrong audience-want false but got true: %v", err)
	} else {
		log.Println(err)
	}
}

func TestTokenExpired(t *testing.T) {
	teardown := testSetup(t)
	defer teardown()

	sub := GetSubject("127.0.0.1", "clientId")
	aud := "jwt.perme.iam.test"
	expIn := "0.1s"
	tokenString, _ := CreateToken(sub, aud, expIn)
	time.Sleep(time.Second)

	if _, err := VerifyToken(tokenString, aud); err == nil {
		t.Errorf("want false but got true: %v", err)
	} else {
		log.Println(err)
	}
}

func TestVerifyTokenBeforeInit(t *testing.T) {
	sub := GetSubject("127.0.0.1", "clientId")
	aud := "jwt.perme.iam.test"
	expIn := "1h"
	tokenString, _ := CreateToken(sub, aud, expIn)
	_, err := VerifyToken(tokenString, aud)
	if err == nil {
		t.Error("want error but got nothing")
	} else {
		log.Println(err)
	}
}
