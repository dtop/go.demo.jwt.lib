package jwt

import (
	"log"
	"net/http"
	"strings"

	gojwt "github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
)

// GinJWTConfig is the config to set before using with gin
var GinJWTConfig *Config

// Access checks the validity of the given token
func Access() gin.HandlerFunc {
	return AccessWithScopes([]string{})
}

// AccessWithScope checks the validity of the token and of a given scope in the token
func AccessWithScope(scope string) gin.HandlerFunc {
	return AccessWithScopes([]string{scope})
}

// AccessWithScopes checks the validity of the token and all given scopes in the token
func AccessWithScopes(scopes []string) gin.HandlerFunc {

	return func(c *gin.Context) {

		var strtok string
		var ok bool

		strtok, ok = getTokenFromHeader(c)
		if !ok {
			strtok, ok = getTokenFromQuery(c)
			if !ok {
				strtok, ok = getTokenFromBody(c)
			}
		}

		if strtok == "" {
			log.Println("no token present")
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		// Check validity of the token itself
		token, err := FromAccessToken(strtok, GinJWTConfig)
		if err != nil {
			log.Println(err)

			_, ok := err.(*gojwt.ValidationError)
			if ok {
				log.Println("token is invalid")
				c.AbortWithStatus(http.StatusUnauthorized)
				return
			}

			c.AbortWithStatus(500)
			return
		}

		// check scopes if any
		if len(scopes) > 0 {

			for _, scope := range scopes {

				if !token.HasScope(scope) {
					log.Println("invalid scope " + scope)
					c.AbortWithStatus(http.StatusUnauthorized)
					return
				}
			}
		}

		c.Set("jwt", token)
		c.Next()
	}
}

func getTokenFromHeader(c *gin.Context) (string, bool) {

	token := c.Request.Header.Get("Authorization")
	token = strings.Replace(token, "Bearer ", "", -1)
	return token, token != ""
}

func getTokenFromBody(c *gin.Context) (string, bool) {

	token := c.DefaultPostForm("jwt", "")
	return token, token != ""
}

func getTokenFromQuery(c *gin.Context) (string, bool) {

	token := c.DefaultQuery("access_token", "")
	if token == "" {
		token = c.DefaultQuery("jwt", "")
	}

	return token, token != ""
}

// GetTokenFromContext straps the token from the context (can be used in endpoints)
func GetTokenFromContext(c *gin.Context) JWT {

	raw, ok := c.Get("jwt")
	if ok {
		return raw.(JWT)
	}

	return nil
}
