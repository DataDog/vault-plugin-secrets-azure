package azuresecrets

import (
	"context"
	"encoding/base64"
	"fmt"
	"github.com/hashicorp/vault/sdk/logical"
	"reflect"
	"testing"
	"time"
)

func Test_decodeAccessToken(t *testing.T) {
	nowEpoch := time.Now().Unix()
	jwt := []byte(fmt.Sprintf("{\"exp\":%v,\"aud\":\"audience\"}", nowEpoch))
	encodedJwt := base64.StdEncoding.WithPadding(base64.NoPadding).EncodeToString(jwt)
	tests := []struct {
		name    string
		token   string
		want    *jws
		wantErr bool
	}{
		{
			name:    "access token decoded",
			token:   fmt.Sprintf("header.%v.signature", encodedJwt),
			want:    &jws{Expiration: nowEpoch},
			wantErr: false,
		},
		{
			name:    "invalid access token",
			token:   fmt.Sprintf("header.%v", encodedJwt),
			want:    nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := decodeAccessToken(tt.token)
			if (err != nil) != tt.wantErr {
				t.Errorf("decodeAccessToken() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("decodeAccessToken() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_azureSecretBackend_pathAccessTokenRead(t *testing.T) {
	b, s := getTestBackend(t, true)

	t.Run("token generated", func(t *testing.T) {
		role := generateUUID()
		testRoleCreate(t, b, s, role, testStaticSPRole)

		resp, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "token/" + role,
			Storage:   s,
		})

		assertErrorIsNil(t, err)

		if resp.IsError() {
			t.Fatalf("receive response error: %v", resp.Error())
		}

		if _, ok := resp.Data["token"]; !ok {
			t.Fatalf("token not found in response")
		}

		if _, ok := resp.Data["token_ttl"]; !ok {
			t.Fatalf("token_ttl not found in response")
		}

		if _, ok := resp.Data["expires_at_seconds"]; !ok {
			t.Fatalf("expires_at_seconds not found in response")
		}
	})

	t.Run("role does not exist", func(t *testing.T) {
		role := generateUUID()
		resp, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "token/" + role,
			Storage:   s,
		})

		assertErrorIsNil(t, err)

		if !resp.IsError() {
			t.Fatal("expected missing role error")
		}
	})
}
