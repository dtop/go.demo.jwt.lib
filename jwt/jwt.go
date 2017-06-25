package jwt

import (
	"log"

	"time"

	"strings"

	gojwt "github.com/dgrijalva/jwt-go"
	"github.com/mendsley/gojwk"
)

type (
	// Config is the config to provide
	Config struct {
		WellKnownAddr string
		KeyStoreFunc  func(string) error
		KeyLoadFunc   func() (string, error)
	}

	// JWT is the token interface
	JWT interface {
		IsValid() bool
		GetUserID() string
		GetScopes() []string
		HasScope(scope string) bool
	}

	jwt struct {
		token   *gojwt.Token
		expires time.Time
		userID  string
		scopes  []string
	}
)

// FromAccessToken generates a usable token from the access token
func FromAccessToken(token string, config *Config) (JWT, error) {

	var key *gojwk.Key
	var err error
	forced := false

	keyPro := NewKeyProvider(config)
	key, err = keyPro.GetKey(forced)
	if key == nil || err != nil {
		forced = true
		log.Println(err)
		key, err = keyPro.GetKey(forced)
		if err != nil {
			return nil, err
		}
	}

	tk, err := gojwt.Parse(token, func(*gojwt.Token) (interface{}, error) {

		return key.DecodePublicKey()
	})

	if err != nil && !forced {

		key, err = keyPro.GetKey(true)
		if err != nil {
			return nil, err
		}

		tk, err = gojwt.Parse(token, func(*gojwt.Token) (interface{}, error) {

			return key.DecodePublicKey()
		})

		if err == nil {
			return NewJWT(tk), nil
		}
	}

	if err != nil {
		return nil, err
	}

	return NewJWT(tk), nil
}

// NewJWT creates an empty JWT
func NewJWT(jwt ...*gojwt.Token) JWT {

	token := &jwt{}
	if len(jwt) > 0 {
		token.token = jwt[0]
	}

	token.init()
	return token
}

// ################################# jwt

func (j *jwt) init() {

	tk := j.token
	claims := tk.Claims.(gojwt.MapClaims)
	for k, v := range claims {

		switch k {

		case "exp":
			j.expires = time.Unix(int64(v), 0)
		case "jti":
			j.userID = v.(string)
		case "sco":
			j.scopes = strings.Split(v.(string), ",")
		}
	}
}

func (j *jwt) IsValid() bool {

	return time.Now().After(j.expires)
}

func (j *jwt) GetUserID() string {
	return j.userID
}

func (j *jwt) GetScopes() []string {
	return j.scopes
}

func (j *jwt) HasScope(scope string) bool {

	for _, iscope := range j.scopes {
		if strings.ToLower(iscope) == strings.ToLower(scope) {
			return true
		}
	}

	return false
}
