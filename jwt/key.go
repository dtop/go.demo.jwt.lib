package jwt

import (
	"net/http"

	"io/ioutil"

	"github.com/mendsley/gojwk"
)

type (

	// KeyProvider provides the .well-known key
	KeyProvider struct {
		config *Config
	}
)

// NewKeyProvider returns a new key provider
func NewKeyProvider(config *Config) *KeyProvider {

	return &KeyProvider{config: config}
}

// GetKey returns the actual key
func (k *KeyProvider) GetKey(forceNew bool) (*gojwk.Key, error) {

	if !forceNew {

		keystr, err := k.getKeyFromCache()
		if err != nil {
			return nil, err
		}

		if keystr != "" {
			return k.makeJWK(keystr)
		}
	}

	keystr, err := k.getKeyFromAddr()
	if err != nil {
		return nil, err
	}

	if k.config.KeyStoreFunc != nil {

		err := k.config.KeyStoreFunc(keystr)
		if err != nil {
			return nil, err
		}
	}

	return k.makeJWK(keystr)
}

func (k *KeyProvider) makeJWK(jwkstr string) (*gojwk.Key, error) {

	key, err := gojwk.Unmarshal([]byte(jwkstr))
	if err != nil {
		return nil, err
	}

	return key, nil
}

func (k *KeyProvider) getKeyFromAddr() (string, error) {

	res, err := http.Get(k.config.WellKnownAddr)
	if err != nil {
		return "", err
	}

	defer res.Body.Close()

	raw, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return "", err
	}

	return string(raw), nil
}

func (k *KeyProvider) getKeyFromCache() (string, error) {

	if nil != k.config.KeyLoadFunc {

		keystr, err := k.config.KeyLoadFunc()
		if err != nil {
			return nil, err
		}

		return keystr, nil
	}

	return "", nil
}
