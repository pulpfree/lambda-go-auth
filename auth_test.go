package auth

import (
	"errors"
	"fmt"
	"testing"

	pkgerrors "github.com/pulpfree/go-errors"
)

var stdError *pkgerrors.StdError

func TestValidate_Success(t *testing.T) {

	expectedPrincipalID := fmt.Sprintf("%s|%s", username, cognitoClientID)

	principalID, err := Validate(validToken, jwksURL)
	if err != nil {
		t.Errorf("Error in TestParse - %+v\n", err)
		return
	}

	if expectedPrincipalID != principalID {
		t.Errorf("Error comparing principalID. Expected: %s got:%v", expectedPrincipalID, principalID)
	}
}

func TestValidate_Expired(t *testing.T) {

	expectMsg := "token invalid"
	_, err := Validate(expiredToken, jwksURL)
	// fmt.Printf("error from test: %s\n", err)
	if ok := errors.As(err, &stdError); ok {
		// fmt.Printf("stdError in test: %s\n", stdError)
		if stdError.Msg != expectMsg {
			t.Errorf("Expect error message to be: %s got %s", expectMsg, stdError.Msg)
		}
	}
	if err == nil {
		t.Error("Expecting expired token")
		return
	}
}

func TestValidate_InvalidToken(t *testing.T) {

	expectMsg := "token invalid"
	_, err := Validate(invalidToken, jwksURL)
	// fmt.Printf("error from test: %s\n", err)
	if ok := errors.As(err, &stdError); ok {
		// fmt.Printf("stdError in test: %v\n", stdError)
		if stdError.Msg != expectMsg {
			t.Errorf("Expect error message to be: %s got %s", expectMsg, stdError.Msg)
		}
	}
	if err == nil {
		t.Error("Expecting error from invalid token")
		return
	}

}

func TestValidate_BadJWKURL(t *testing.T) {

	expectMsg := "token invalid"
	_, err := Validate(validToken, badJwksURL)
	// fmt.Printf("error from test: %s\n", err)
	// fmt.Printf("err.Err: %+v\n", err.Error())
	if ok := errors.As(err, &stdError); ok {
		if stdError.Msg != expectMsg {
			t.Errorf("Expect error message to be: %s got %s", expectMsg, stdError.Msg)
		}
	}
	if err == nil {
		t.Error("Expecting error from bad jwk url")
		return
	}

}
