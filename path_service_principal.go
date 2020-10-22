package azuresecrets

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/Azure/go-autorest/autorest/to"
	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/locksutil"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	SecretTypeSP       = "service_principal"
	SecretTypeStaticSP = "static_service_principal"
)

// SPs will be created with a far-future expiration in Azure
var spExpiration = 10 * 365 * 24 * time.Hour

func secretServicePrincipal(b *azureSecretBackend) *framework.Secret {
	return &framework.Secret{
		Type:   SecretTypeSP,
		Renew:  b.spRenew,
		Revoke: b.spRevoke,
	}
}

func secretStaticServicePrincipal(b *azureSecretBackend) *framework.Secret {
	return &framework.Secret{
		Type:   SecretTypeStaticSP,
		Renew:  b.spRenew,
		Revoke: b.staticSPRevoke,
	}
}

func pathServicePrincipal(b *azureSecretBackend) *framework.Path {
	return &framework.Path{
		Pattern: fmt.Sprintf("creds/%s", framework.GenericNameRegex("role")),
		Fields: map[string]*framework.FieldSchema{
			"role": {
				Type:        framework.TypeLowerCaseString,
				Description: "Name of the Vault role",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathSPRead,
			},
		},
		HelpSynopsis:    pathServicePrincipalHelpSyn,
		HelpDescription: pathServicePrincipalHelpDesc,
	}
}

// pathSPRead generates Azure credentials based on the role credential type.
func (b *azureSecretBackend) pathSPRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	client, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	roleName := d.Get("role").(string)

	role, err := getRole(ctx, roleName, req.Storage)
	if err != nil {
		return nil, err
	}

	if role == nil {
		return logical.ErrorResponse(fmt.Sprintf("role '%s' does not exist", roleName)), nil
	}

	var secretType string
	switch role.ApplicationType {
	case applicationTypeStatic:
		err = b.createStaticSPSecret(ctx, client, role)
		secretType = SecretTypeStaticSP
	case applicationTypeDynamic:
		err = b.createSPSecret(ctx, client, role)
		secretType = SecretTypeSP
	default:
		return nil, fmt.Errorf("unknown role ApplicationType \"%v\"", role.ApplicationType)
	}

	if err != nil {
		return nil, err
	}

	data := map[string]interface{}{
		"client_id":     role.ApplicationID,
		"client_secret": role.Credentials.Password,
	}
	internalData := map[string]interface{}{
		"app_object_id":        role.ApplicationObjectID,
		"key_id":               role.Credentials.KeyId,
		"sp_object_id":         role.ServicePrincipalID,
		"role_assignment_ids":  roleIDs(role.AzureRoles),
		"group_membership_ids": groupObjectIDs(role.AzureGroups),
		"role":                 roleName,
	}
	resp := b.Secret(secretType).Response(data, internalData)
	resp.Secret.TTL = role.TTL
	resp.Secret.MaxTTL = role.MaxTTL

	return resp, nil
}

// createSPSecret generates a new App/Service Principal.
func (b *azureSecretBackend) createSPSecret(ctx context.Context, c *client, role *roleEntry) error {
	// Create the App, which is the top level object to be tracked in the secret
	// and deleted upon revocation. If any subsequent step fails, the App is deleted.
	app, err := c.createApp(ctx)
	if err != nil {
		return err
	}
	appID := to.String(app.AppID)
	appObjID := to.String(app.ObjectID)

	// Create a service principal associated with the new App
	sp, password, err := c.createSP(ctx, app, spExpiration)
	if err != nil {
		c.deleteApp(ctx, appObjID)
		return err
	}

	role.ApplicationID = appID
	role.ApplicationObjectID = appObjID
	role.ServicePrincipalID = to.String(sp.ObjectID)
	role.Credentials = &ClientCredentials{
		Password: password,
	}

	return nil
}

// createStaticSPSecret adds a new password to the App associated with the role.
func (b *azureSecretBackend) createStaticSPSecret(ctx context.Context, c *client, role *roleEntry) error {
	lock := locksutil.LockForKey(b.appLocks, role.ApplicationObjectID)
	lock.Lock()
	defer lock.Unlock()

	keyID, password, err := c.addAppPassword(ctx, role.ApplicationObjectID, spExpiration)
	if err != nil {
		return err
	}

	role.Credentials = &ClientCredentials{
		KeyId:    keyID,
		Password: password,
	}

	return nil
}

func (b *azureSecretBackend) spRenew(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	roleRaw, ok := req.Secret.InternalData["role"]
	if !ok {
		return nil, errors.New("internal data 'role' not found")
	}

	role, err := getRole(ctx, roleRaw.(string), req.Storage)
	if err != nil {
		return nil, err
	}

	if role == nil {
		return nil, nil
	}

	resp := &logical.Response{Secret: req.Secret}
	resp.Secret.TTL = role.TTL
	resp.Secret.MaxTTL = role.MaxTTL

	return resp, nil
}

func (b *azureSecretBackend) spRevoke(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	appObjectIDRaw, ok := req.Secret.InternalData["app_object_id"]
	if !ok {
		return nil, errors.New("internal data 'app_object_id' not found")
	}

	appObjectID := appObjectIDRaw.(string)

	// Get the service principal object ID. Only set if using dynamic service
	// principals.
	var spObjectID string
	if spObjectIDRaw, ok := req.Secret.InternalData["sp_object_id"]; ok {
		spObjectID = spObjectIDRaw.(string)
	}

	var roles []*AzureRole
	if req.Secret.InternalData["role_assignment_ids"] != nil {
		for _, v := range req.Secret.InternalData["role_assignment_ids"].([]interface{}) {
			roles = append(roles, &AzureRole{
				RoleID: v.(string),
			})
		}
	}

	var groups []*AzureGroup
	if req.Secret.InternalData["group_membership_ids"] != nil {
		for _, v := range req.Secret.InternalData["group_membership_ids"].([]interface{}) {
			groups = append(groups, &AzureGroup{
				ObjectID: v.(string),
			})
		}
	}

	r := &roleEntry{
		AzureRoles:          roles,
		AzureGroups:         groups,
		ApplicationObjectID: appObjectID,
		ServicePrincipalID:  spObjectID,
	}

	return b.spRemove(ctx, req, r)
}

func (b *azureSecretBackend) spRemove(ctx context.Context, req *logical.Request, role *roleEntry) (*logical.Response, error) {
	if len(role.AzureGroups) != 0 && role.ServicePrincipalID == "" {
		return nil, errors.New("service principal ID not found")
	}

	c, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return nil, errwrap.Wrapf("error during revoke: {{err}}", err)
	}

	resp := new(logical.Response)
	// unassigning roles is effectively a garbage collection operation. Errors will be noted but won't fail the
	// revocation process. Deleting the app, however, *is* required to consider the secret revoked.
	if err := c.unassignRoles(ctx, role.AzureRoles); err != nil {
		resp.AddWarning(err.Error())
	}

	// removing group membership is effectively a garbage collection
	// operation. Errors will be noted but won't fail the revocation process.
	// Deleting the app, however, *is* required to consider the secret revoked.
	if err := c.removeGroupMemberships(ctx, role.ServicePrincipalID, role.AzureGroups); err != nil {
		resp.AddWarning(err.Error())
	}

	err = c.deleteApp(ctx, role.ApplicationObjectID)
	return resp, err
}

func (b *azureSecretBackend) staticSPRevoke(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	appObjectIDRaw, ok := req.Secret.InternalData["app_object_id"]
	if !ok {
		return nil, errors.New("internal data 'app_object_id' not found")
	}
	appObjectID := appObjectIDRaw.(string)

	keyIDRaw, ok := req.Secret.InternalData["key_id"]
	if !ok {
		return nil, errors.New("internal data 'key_id' not found")
	}

	lock := locksutil.LockForKey(b.appLocks, appObjectID)
	lock.Lock()
	defer lock.Unlock()

	r := &roleEntry{
		ApplicationObjectID: appObjectID,
		Credentials: &ClientCredentials{
			KeyId: keyIDRaw.(string),
		},
	}

	return b.staticSPRemove(ctx, req, r)
}

func (b *azureSecretBackend) staticSPRemove(ctx context.Context, req *logical.Request, role *roleEntry) (*logical.Response, error) {
	c, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return nil, errwrap.Wrapf("error during revoke: {{err}}", err)
	}

	return nil, c.deleteAppPassword(ctx, role.ApplicationObjectID, role.Credentials.KeyId)
}

const pathServicePrincipalHelpSyn = `
Request Service Principal credentials for a given Vault role.
`

const pathServicePrincipalHelpDesc = `
This path creates or updates dynamic Service Principal credentials.
The associated role can be configured to create a new App/Service Principal,
or add a new password to an existing App. The Service Principal or password
will be automatically deleted when the lease has expired.
`
