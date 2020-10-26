# Token

JSON Web Token Interface built on top of jwt-go

[![PkgGoDev](https://pkg.go.dev/badge/github.com/JuneKimDev/token)](https://pkg.go.dev/github.com/JuneKimDev/token)
[![Go Report Card](https://goreportcard.com/badge/github.com/JuneKimDev/token)](https://goreportcard.com/report/github.com/JuneKimDev/token)
![GitHub tag (latest by date)](https://img.shields.io/github/v/tag/JuneKimDev/token)
![GitHub](https://img.shields.io/github/license/JuneKimDev/token)

---

## Getting Started

### Prerequisite

Create a private and public key pair in root directory

> e.g. creating RSA key pair via `openssl`

```shell
openssl genrsa -out rsa_prv.key 2048 && openssl rsa -RSAPublicKey_out -in rsa_prv.key -out rsa_pub.key
```

### Installing

go get it (pun intended :smile_cat:)

```shell
go get github.com/JuneKimDev/token
```

## Usage

```golang
package main

import (
  "log"

  "github.com/JuneKimDev/token"
)

func init(){
  // For token issuer
  if err := token.InitPrvKey("rsa_prv.key"); err != nil {
    log.Fatal(err)
  }
  // For token verifier
  if err := token.InitPubKey("rsa_prv.key"); err != nil {
    log.Fatal(err)
  }
}

func issue() (string, error){
  subIP := "127.0.0.1"
  subID := "clientId"

  sub := token.GetSubject(subIP, subID)
  aud := "test.aud"
  expIn := "1h"
  return token.Create(sub, aud, expIn)
}

func main() {
  // tokenstring from http request
  subject, err = token.Verify(tokenstring)
  if err != nil {
    log.Println(err)
  }

  userIP, userID := token.ParseSubject(subject)
  // Do something with it
}
```
