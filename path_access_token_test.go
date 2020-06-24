package azuresecrets

import (
	"context"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

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

		if _, ok := resp.Data["access_token"]; !ok {
			t.Fatalf("access_token not found in response")
		}

		if _, ok := resp.Data["refresh_token"]; !ok {
			t.Fatalf("refresh_token not found in response")
		}

		if _, ok := resp.Data["expires_in"]; !ok {
			t.Fatalf("expires_in not found in response")
		}

		if _, ok := resp.Data["expires_on"]; !ok {
			t.Fatalf("expires_on not found in response")
		}

		if _, ok := resp.Data["not_before"]; !ok {
			t.Fatalf("not_before not found in response")
		}

		if _, ok := resp.Data["resource"]; !ok {
			t.Fatalf("resource not found in response")
		}

		if _, ok := resp.Data["token_type"]; !ok {
			t.Fatalf("token_type not found in response")
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
