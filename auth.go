package auth

import (
	"crypto/rsa"
	"errors"
	"fmt"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/lestrrat-go/jwx/jwk"
	pkgerrors "github.com/pulpfree/go-errors"
	log "github.com/sirupsen/logrus"
)

// https://cognito-idp.{region}.amazonaws.com/{userPoolId}/.well-known/jwks.json

var keySet *jwk.Set

// Validate method
func Validate(tokenString, jwksURL string) (principalID string, err error) {

	/**
	to display friendly errors when using package, do following
	var stdError *pkgerrors.StdError
	if ok := errors.As(err, &stdError); ok {
		log.Errorf("%s", stdError.Msg)
	}
	*/

	type CustomClaims struct {
		jwt.StandardClaims
		ClientID string `json:"client_id"`
		Username string `json:"username"`
		Scope    string `json:"scope"`
	}

	token, err := jwt.ParseWithClaims(tokenString, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {

		key, err := getKey(token, jwksURL)
		if err != nil {
			return nil, err
		}
		return key.(*rsa.PublicKey), nil
	})
	if !token.Valid {
		return "", &pkgerrors.StdError{Err: err.Error(), Caller: "jwt.ParseWithClaims", Msg: "token invalid"}
	}

	if claims, ok := token.Claims.(*CustomClaims); ok && token.Valid {
		principalID = fmt.Sprintf("%s|%s", claims.Username, claims.ClientID)
		return principalID, nil
	}

	return principalID, err
}

func getKeySet(jwksURL string) (set *jwk.Set, err error) {
	set, err = jwk.FetchHTTP(jwksURL)
	if err != nil {
		return nil, &pkgerrors.StdError{Err: err.Error(), Caller: jwksURL, Msg: "Error while fetching jwks"}
	}
	return set, err
}

func getKey(token *jwt.Token, jwksURL string) (interface{}, error) {

	keyID, ok := token.Header["kid"].(string)
	if !ok {
		errMsg := errors.New("expecting JWT header to have string kid")
		return nil, &pkgerrors.StdError{Err: errMsg.Error(), Caller: "getKey", Msg: "Error while getting key"}
	}

	keySet, err := getKeySet(jwksURL)
	if err != nil {
		return nil, err
	}

	keys := keySet.LookupKeyID(keyID)
	if len(keys) == 0 {
		errMsg := fmt.Errorf("failed to lookup key with id: %s", keyID)
		return nil, &pkgerrors.StdError{Err: errMsg.Error(), Caller: "keySet.LookupKeyID", Msg: "Error while getting key"}
	}

	var key interface{}
	if err := keys[0].Raw(&key); err != nil {
		log.Printf("failed to generate public key: %s", err)
		return nil, &pkgerrors.StdError{Err: err.Error(), Caller: "keys[0].Raw", Msg: "Error while getting key"}
	}

	return key, nil
}
