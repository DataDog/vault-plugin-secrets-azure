package azuresecrets

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	azureadal "github.com/Azure/go-autorest/autorest/adal"
	azureauth "github.com/Azure/go-autorest/autorest/azure/auth"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	azureAppNotFoundErrCode = 700016
)

func pathAccessToken(b *azureSecretBackend) *framework.Path {
	return &framework.Path{
		Pattern: fmt.Sprintf("token/%s", framework.GenericNameRegex("role")),
		Fields: map[string]*framework.FieldSchema{
			"role": {
				Type:        framework.TypeLowerCaseString,
				Description: "Name of the Vault role",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathAccessTokenRead,
			},
		},
		HelpSynopsis:    pathAccessTokenHelpSyn,
		HelpDescription: pathAccessTokenHelpDesc,
	}
}

func (b *azureSecretBackend) pathAccessTokenRead(ctx context.Context, request *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("role").(string)

	role, err := getRole(ctx, roleName, request.Storage)
	if err != nil {
		return nil, err
	}

	if role == nil {
		return logical.ErrorResponse("role '%s' does not exist", roleName), nil
	}

	if role.CredentialType != credentialTypeSP {
		return logical.ErrorResponse("role '%s' cannot generate access tokens (has secret type %s)", roleName, role.CredentialType), nil
	}

	return b.secretAccessTokenResponse(ctx, request.Storage, role)
}

func (b *azureSecretBackend) secretAccessTokenResponse(ctx context.Context, storage logical.Storage, role *roleEntry) (*logical.Response, error) {
	client, err := b.getClient(ctx, storage)
	if err != nil {
		return nil, err
	}

	cc := azureauth.NewClientCredentialsConfig(role.ApplicationID, role.Credentials.Password, client.settings.TenantID)
	token, err := b.getToken(ctx, client, cc)
	if err != nil {
		return nil, err
	}

	j, err := decodeAccessToken(token.AccessToken)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	exp := time.Unix(j.Expiration, 0)
	ttl := math.Max(exp.Sub(now).Truncate(time.Second).Seconds(), 0)

	// access_tokens are not revocable therefore do not return a framework.Secret (i.e. a lease)
	return &logical.Response{
		Data: map[string]interface{}{
			"token":              token.AccessToken,
			"token_ttl":          ttl,
			"expires_at_seconds": j.Expiration,
		},
	}, nil
}

func decodeAccessToken(token string) (*jws, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("invalid JWT from Azure")
	}

	decodedToken, err := base64.StdEncoding.WithPadding(base64.NoPadding).DecodeString(parts[1])
	if err != nil {
		return nil, err
	}

	j := &jws{}
	err = json.Unmarshal(decodedToken, j)
	if err != nil {
		return nil, err
	}

	return j, nil
}

type jws struct {
	// Expiration is the Epoch when the JWT expires
	Expiration int64 `json:"exp"`
}

func (b *azureSecretBackend) getToken(ctx context.Context, client *client, c azureauth.ClientCredentialsConfig) (azureadal.Token, error) {
	token, err := retry(ctx, func() (interface{}, bool, error) {
		t, err := client.provider.GetToken(c)

		if hasAzureErrorCode(err, azureAppNotFoundErrCode) {
			return nil, false, nil
		} else if err != nil {
			return nil, true, err
		}

		return t, true, nil
	})

	var t azureadal.Token
	if token != nil {
		t = token.(azureadal.Token)
	}

	return t, err
}

func hasAzureErrorCode(e error, code int) bool {
	tErr, ok := e.(azureadal.TokenRefreshError)

	// use a pattern match as TokenRefreshError is not easily parsable
	return ok && tErr != nil && strings.Contains(tErr.Error(), fmt.Sprint(code))
}

const pathAccessTokenHelpSyn = `
Request an access token for a given Vault role.
`

const pathAccessTokenHelpDesc = `
This path creates access token credentials. The associated role must
be created ahead of time with either an existing App/Service Principal or 
else a dynamic Service Principal will be created.
`
