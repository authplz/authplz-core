package token

import "testing"
import "time"

import "github.com/satori/go.uuid"

func TestToken(t *testing.T) {

    var fakeHmacKey = "Test hmac FTW"

    tc := NewTokenController(fakeHmacKey)

    var fakeUuid = uuid.NewV4().String();

    // Run tests
    t.Run("Generates tokens", func(t *testing.T) {
        t.Error("boop")
        d, _ := time.ParseDuration("10m")
        token, err := tc.BuildToken(fakeUuid, "activate", d);
        if err != nil {
            t.Error(err)
        }
        if token != nil {
            t.Error("Token creation failed")
        }
    })


}
