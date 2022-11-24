/*
Copyright (c) 2022 Gemba Advantage
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

package main

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
)

var (
	keycloakRealmURL = os.Getenv("KEYCLOAK_REALM_URL")
	publicKey        []byte
)

type keycloakRealm struct {
	PublicKey []byte `json:"public_key"`
}

func init() {
	// Temporary hack to ignore self-signed certificates
	cfg := &tls.Config{
		InsecureSkipVerify: true,
	}
	http.DefaultClient.Transport = &http.Transport{
		TLSClientConfig: cfg,
	}
}

func main() {
	// Query the keycloak Realm upon startup and extract the public key
	resp, err := http.Get(keycloakRealmURL)
	if err != nil {
		log.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	var realm keycloakRealm
	json.Unmarshal(body, &realm)

	// Build the final public key and ensure it is wrapped as needed
	key := strings.Builder{}
	key.WriteString("-----BEGIN RSA PUBLIC KEY-----\n")
	key.Write(realm.PublicKey)
	key.WriteString("\n-----END RSA PUBLIC KEY-----")
	publicKey = []byte(key.String())

	r := gin.Default()
	r.GET("/", func(c *gin.Context) {
		out := strings.Builder{}

		req, _ := httputil.DumpRequest(c.Request, false)
		out.Write(req)

		if auth, ok := c.Request.Header["Authorization"]; ok {
			bearer := strings.TrimPrefix(auth[0], "Bearer ")

			key, err := pemToKey(publicKey)
			if err != nil {
				fmt.Println(err)
			}
			decoded, err := decodeJWT(bearer, key)
			if err != nil {
				fmt.Println(err)
			}

			out.WriteByte('\n')
			out.WriteString(decoded.Raw)
		}

		c.String(http.StatusOK, out.String())
	})
	r.Run()
}

func pemToKey(pemData []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode public key in PEM format")
	}

	parsedKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse RSA public key: %v", err)
	}

	if rsaPublicKey, ok := parsedKey.(*rsa.PublicKey); ok {
		return rsaPublicKey, nil
	}

	return nil, fmt.Errorf("public key is not an RSA one")
}

func decodeJWT(bearerToken string, publicKey *rsa.PublicKey) (*jwt.Token, error) {
	token, err := jwt.Parse(bearerToken, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return publicKey, nil
	})

	return token, err
}
