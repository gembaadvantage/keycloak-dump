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
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
)

var (
	keycloakRealmURL = os.Getenv("KEYCLOAK_REALM_URL")
	publicKey        = ""
)

type keycloakRealm struct {
	PublicKey string `json:"public_key"`
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

	r := gin.Default()
	r.GET("/", func(c *gin.Context) {
		out := strings.Builder{}

		req, _ := httputil.DumpRequest(c.Request, false)
		out.Write(req)

		if auth, ok := c.Request.Header["Authorization"]; ok {
			out.WriteByte('\n')
			out.WriteString(auth[0])

			// TODO: decode the jwt
		}

		c.String(http.StatusOK, out.String())
	})
	r.Run()
}
