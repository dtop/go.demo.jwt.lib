# go.demo.jwt.lib

Library for validating the tokens issued by [go.demo.iam](https://github.com/dtop/go.demo.iam)
for the "How to build an IAM service" [tutorial](https://www.youtube.com/watch?v=KaYu4yxk2tQ&list=PLfWOND62Ti-cfmjwAXhhdLFtKo32i2Oio) 

### INSTALL

```
$ go get github.com/dtop/go.demo.jwt.lib
```

### USAGE

```go

package foo

import (
    "github.com/dtop/go.demo.jwt.lib/jwt"
    "github.com/gin-gonic/gin"
)

func SetupGin() *gin.Engine {

    
    jwt.GinJWTConfig = &jwt.Config{
        WellKnownAddr: "https://iamserver.org//iam/.well-known/key",
        KeyStoreFunc:  func(string) error {
            // cache string
            return nil
        },
        KeyLoadFunc: func() (string, error) {
            var strtok string
            // load string
            return strtok, nil
        },
    }


    gin := gin.New()
    // checks validity only
    gin.GET("/foo", jwt.Access(), MyEndpoint)
    // checks validity and scopes
    gin.POST("/other", jwt.AccessWithScopes([]string{"canReadMail", "canDeleteMail"}), OtherEndpoint)
    
    return gin 
}

func MyEndpoint(c *gin.Context) {

    token := jwt.GetTokenFromContext(c)
    if token != nil {
        // ... use the token   
    }
}

func OtherEndpoint(c *gin.Context) {

}

```
