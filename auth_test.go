package auth

import (
	"errors"
	"fmt"
	"testing"

	pkgerrors "github.com/pulpfree/go-errors"
)

// https://cognito-idp.ca-central-1.amazonaws.com/ca-central-1_lolwfYIAr/.well-known/jwks.json

const (
	cognitoClientID = "5n63nd473pv7ne2qskv30gkcbh" // gdips client id
	jwksURL         = "https://cognito-idp.ca-central-1.amazonaws.com/ca-central-1_lolwfYIAr/.well-known/jwks.json"
	badJwksURL      = "https://cognito-idp.ca-central-1.amazonaws.com//.well-known/jwks.json"
	username        = "pulpfree" // expected username associated with token
	invalidToken    = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIiLCJleHAiOjE1MDAwLCJpc3MiOiJ0ZXN0In0.HE7fK0xOQwFEr4WDgRWj4teRPZ6i3GLwD5YCm6Pwu_c"
	expiredToken    = "eyJraWQiOiI3SUh0cXdKRThJVHg3MXJEdkJCRkgrUTByNm5DZXd5ZERqVWpUZ0ZjNFhFPSIsImFsZyI6IlJTMjU2In0.eyJzdWIiOiIyYThkYWE0ZC1hMGNhLTQ0MWUtYjA3OS03YmE5MjNkZmZjYzkiLCJkZXZpY2Vfa2V5IjoiY2EtY2VudHJhbC0xX2IwY2JlODg1LWJkYmMtNDBmZi05OTA0LTg4ZDVkYTU1NDNiYiIsInRva2VuX3VzZSI6ImFjY2VzcyIsInNjb3BlIjoiYXdzLmNvZ25pdG8uc2lnbmluLnVzZXIuYWRtaW4iLCJhdXRoX3RpbWUiOjE1OTgzMDA2MzAsImlzcyI6Imh0dHBzOlwvXC9jb2duaXRvLWlkcC5jYS1jZW50cmFsLTEuYW1hem9uYXdzLmNvbVwvY2EtY2VudHJhbC0xX2xvbHdmWUlBciIsImV4cCI6MTU5OTA3MTc1NCwiaWF0IjoxNTk5MDY4MTU1LCJqdGkiOiI1NDkzYjdkOS01ZDBjLTQ3ZmEtYTNiMC1jN2RlMGIzZWNkZDMiLCJjbGllbnRfaWQiOiI1bjYzbmQ0NzNwdjduZTJxc2t2MzBna2NiaCIsInVzZXJuYW1lIjoicHVscGZyZWUifQ.rtH7bOhTiRJElJSFTStprVNgiylWfRmnLrsR3lTUe_2jggQQdusNurF5usZBoxpelO2g2xIQAD68MIfhY54ctOeWE0P-y81zEtvSPUQI2cNkN8jnoBCD95XcUKnuXZvNtFGRe7tXHNcH6GP2QWAUuIhO2fb8SbSYcBxxW2QqcBirWBbd0qbATJ8TLz5PYqWOD9YWLckDItJuTDycMXYwYL7lglDybaMmiD6Z7JKiKdnpBFwg9UNQVJg8UvXCZaBluUWMb4YfPg-gYtytco8BlI0X721DhaXr8PKAm-c6ZSXXnzsXqPCiBpjcbYiIQvPkOwVBvmu7IHEEbHhbOeE8OQ"
	validToken      = "eyJraWQiOiI3SUh0cXdKRThJVHg3MXJEdkJCRkgrUTByNm5DZXd5ZERqVWpUZ0ZjNFhFPSIsImFsZyI6IlJTMjU2In0.eyJzdWIiOiIyYThkYWE0ZC1hMGNhLTQ0MWUtYjA3OS03YmE5MjNkZmZjYzkiLCJkZXZpY2Vfa2V5IjoiY2EtY2VudHJhbC0xX2IwY2JlODg1LWJkYmMtNDBmZi05OTA0LTg4ZDVkYTU1NDNiYiIsInRva2VuX3VzZSI6ImFjY2VzcyIsInNjb3BlIjoiYXdzLmNvZ25pdG8uc2lnbmluLnVzZXIuYWRtaW4iLCJhdXRoX3RpbWUiOjE1OTgzMDA2MzAsImlzcyI6Imh0dHBzOlwvXC9jb2duaXRvLWlkcC5jYS1jZW50cmFsLTEuYW1hem9uYXdzLmNvbVwvY2EtY2VudHJhbC0xX2xvbHdmWUlBciIsImV4cCI6MTU5OTE0NTMyMiwiaWF0IjoxNTk5MTQxNzIyLCJqdGkiOiI3MjhiMzNiNy0xNzgyLTRiZjYtYjUwOC00Y2Q4NzY5NTM1MjgiLCJjbGllbnRfaWQiOiI1bjYzbmQ0NzNwdjduZTJxc2t2MzBna2NiaCIsInVzZXJuYW1lIjoicHVscGZyZWUifQ.Xz3yeonwTRMHTM0eG17CfPNQj_DiTdzlruRT8eEOzvzi9b2GU3edLpJghL_dd0w5jWNnNzEHL8zRnSXDjtIVakCpXqIzuDf3DCd7kX3bsBxyDzbRAsoditQOjaBwy8k8jwfqa3ekqbNGUNa4pxJr4t0eQSnO7QortlohH_pHYV1qRqMR75pJsLOfFrPd3G4j1dw862Jx0pU9nO76AqHJ9VOIJA6_jcCvDtEPcSHg7T4QvVJVHV_bTjC1H6B96zMB3sfqAnViUbu0Lt_S8VVRYLITvRItcbJnjdoMgZJ4BJ1p61hQWaRjO_KmoNlp1x9NvvRzGZuuVOjQNdnNWrpNUQ"
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
