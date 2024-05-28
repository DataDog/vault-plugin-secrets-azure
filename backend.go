package azuresecrets

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/vault-plugin-secrets-azure/api"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/consts"
	"github.com/hashicorp/vault/sdk/helper/locksutil"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	spCredCheckCooldown = time.Hour * 4
	spCredsRfreshBuffer = time.Hour * 24 * 7 // one week
)

type azureSecretBackend struct {
	*framework.Backend

	getProvider func(*clientSettings, api.Passwords) (api.AzureProvider, error)
	client      *client
	settings    *clientSettings
	lock        sync.RWMutex

	// Creating/deleting passwords against a single Application is a PATCH
	// operation that must be locked per Application Object ID.
	appLocks       []*locksutil.LockEntry
	updatePassword bool

	nextSPCredCheck time.Time
}

func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := backend()
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

func backend() *azureSecretBackend {
	var b = azureSecretBackend{
		updatePassword: true,
	}

	b.Backend = &framework.Backend{
		Help: strings.TrimSpace(backendHelp),
		PathsSpecial: &logical.Paths{
			SealWrapStorage: []string{
				"config",
			},
		},
		Paths: framework.PathAppend(
			pathsRole(&b),
			[]*framework.Path{
				pathAccessToken(&b),
				pathConfig(&b),
				pathServicePrincipal(&b),
				pathRotateRoot(&b),
			},
		),
		Secrets: []*framework.Secret{
			secretServicePrincipal(&b),
			secretStaticServicePrincipal(&b),
		},
		BackendType: logical.TypeLogical,
		Invalidate:  b.invalidate,

		// Role assignment can take up to a few minutes, so ensure we don't try
		// to roll back during creation.
		WALRollbackMinAge: 10 * time.Minute,

		WALRollback:  b.walRollback,
		PeriodicFunc: b.periodicFunc,
	}
	b.getProvider = newAzureProvider
	b.appLocks = locksutil.CreateLocks()

	return &b
}

func (b *azureSecretBackend) periodicFunc(ctx context.Context, sys *logical.Request) error {
	// Root rotation through the periodic func writes to storage. Only run this on the
	// active instance in the primary cluster or local mounts. The periodic func doesn't
	// run on perf standbys or DR secondaries, but we still protect against this here.
	replicationState := b.System().ReplicationState()
	if (b.System().LocalMount() || !replicationState.HasState(consts.ReplicationPerformanceSecondary)) &&
		!replicationState.HasState(consts.ReplicationDRSecondary) &&
		!replicationState.HasState(consts.ReplicationPerformanceStandby) {

		b.Logger().Debug("starting periodic func")

		err := b.rotateRootCreds(ctx, sys.Storage)
		if err != nil {
			b.Logger().Error("rotate root credentials failed", "error", err)
			return err
		}

		if b.nextSPCredCheck.IsZero() || !time.Now().Before(b.nextSPCredCheck) {
			b.Logger().Debug("refreshing service principal credentials")

			err = b.refreshSPCredentials(ctx, sys.Storage)
			if err != nil {
				b.Logger().Error("refresh service principal credentials failed", "error", err)
				return err
			}

			// Update the time at which to run the cred check again.
			b.nextSPCredCheck = time.Now().Add(spCredCheckCooldown)
		}
	}

	return nil
}

func (b *azureSecretBackend) rotateRootCreds(ctx context.Context, storage logical.Storage) error {
	if !b.updatePassword {
		b.Logger().Debug("periodic func", "rotate-root", "no rotate-root update")
		return nil
	}

	config, err := b.getConfig(ctx, storage)
	if err != nil {
		return err
	}

	// Config can be nil if deleted or when the engine is enabled
	// but not yet configured.
	if config == nil {
		return nil
	}

	// Password should be at least a minute old before we process it
	if config.NewClientSecret == "" || (time.Since(config.NewClientSecretCreated) < time.Minute) {
		return nil
	}

	b.Logger().Debug("periodic func", "rotate-root", "new password detected, swapping in storage")
	client, err := b.getClient(ctx, storage)
	if err != nil {
		return err
	}

	apps, err := client.provider.ListApplications(ctx, fmt.Sprintf("appId eq '%s'", config.ClientID))
	if err != nil {
		return err
	}

	if len(apps) == 0 {
		return fmt.Errorf("no application found")
	}
	if len(apps) > 1 {
		return fmt.Errorf("multiple applications found - double check your client_id")
	}

	app := apps[0]

	credsToDelete := []string{}
	for _, cred := range app.PasswordCredentials {
		if *cred.KeyID != config.NewClientSecretKeyID {
			credsToDelete = append(credsToDelete, *cred.KeyID)
		}
	}

	if len(credsToDelete) != 0 {
		b.Logger().Debug("periodic func", "rotate-root", "removing old passwords from Azure")
		err = removeApplicationPasswords(ctx, client.provider, *app.ID, credsToDelete...)
		if err != nil {
			return err
		}
	}

	b.Logger().Debug("periodic func", "rotate-root", "updating config with new password")
	config.ClientSecret = config.NewClientSecret
	config.ClientSecretKeyID = config.NewClientSecretKeyID
	config.RootPasswordExpirationDate = config.NewClientSecretExpirationDate
	config.NewClientSecret = ""
	config.NewClientSecretKeyID = ""
	config.NewClientSecretCreated = time.Time{}

	err = b.saveConfig(ctx, config, storage)
	if err != nil {
		return err
	}

	b.updatePassword = false

	return nil
}

func (b *azureSecretBackend) refreshSPCredentials(ctx context.Context, storage logical.Storage) error {
	roleNames, err := storage.List(ctx, rolesStoragePath+"/")
	if err != nil {
		return fmt.Errorf("error listing roles: %w", err)
	}

	b.Logger().Debug("listed roles", "roles", roleNames)

	expirationCutoff := time.Now().Add(spCredsRfreshBuffer)
	for _, roleName := range roleNames {
		err = b.refreshSPCredentialsForRole(ctx, storage, roleName, expirationCutoff)
		if err != nil {
			b.Logger().Error("failed to refresh service principal credentials for role", "role", roleName, "error", err)
		}
	}

	return nil
}

func (b *azureSecretBackend) refreshSPCredentialsForRole(ctx context.Context, storage logical.Storage, roleName string, expirationCutoff time.Time) error {
	lock := locksutil.LockForKey(b.appLocks, roleName)
	lock.Lock()
	defer lock.Unlock()

	client, err := b.getClient(ctx, storage)
	if err != nil {
		return err
	}

	b.Logger().Debug("checking service principal credentials", "role", roleName)

	role, err := getRole(ctx, roleName, storage)
	if err != nil {
		return fmt.Errorf("failed to get role %q: %w", roleName, err)
	}

	if role.ApplicationType != applicationTypeDynamic {
		return nil
	} else if role.Credentials == nil {
		// This should be impossible
		return fmt.Errorf("dynamic application role missing credentials. role: %s", roleName)
	}

	if role.Credentials.ExpiresAt.After(expirationCutoff) {
		return nil
	}

	b.Logger().Debug("retrieving service principal", "id", role.ServicePrincipalID)
	servicePrincipal, err := client.getSP(ctx, role.ServicePrincipalID)
	if err != nil {
		return fmt.Errorf("error getting service principal: %w", err)
	}

	// we don't have the keyID and the service principal has a single password that hasn't expired, so we assume that is the
	// password we are currently using and update the role.
	if role.Credentials.KeyId == "" && len(servicePrincipal.PasswordCredentials) == 1 && servicePrincipal.PasswordCredentials[0].EndDate.After(expirationCutoff) {
		cred := servicePrincipal.PasswordCredentials[0]
		role.Credentials.KeyId = *cred.KeyID
		role.Credentials.ExpiresAt = cred.EndDate.ToTime()

		err = saveRole(ctx, storage, role, roleName)
		if err != nil {
			return fmt.Errorf("failed to save role %q: %w", roleName, err)
		}
		b.Logger().Debug("updated role credentials", "role", roleName)
		return nil
	}

	currPassword, ok := findPasswordWithID(role.Credentials.KeyId, servicePrincipal.PasswordCredentials)
	if !ok || currPassword.EndDate.Before(expirationCutoff) {
		// we don't know what password we are using or it is expiring so refresh it

		newPassword, err := client.addSPPassword(ctx, role.ServicePrincipalID, spExpiration)
		if err != nil {
			return fmt.Errorf("failed to add new service principal password for role %q: %w", roleName, err)
		}
		b.Logger().Debug("added new service principal credentials", "role", roleName)

		role.Credentials = &ClientCredentials{
			KeyId:     *newPassword.KeyID,
			Password:  *newPassword.SecretText,
			ExpiresAt: newPassword.EndDate.ToTime(),
		}
		err = saveRole(ctx, storage, role, roleName)
		if err != nil {
			// try to remove the new password
			err = client.removeSPPassword(ctx, role.ServicePrincipalID, *newPassword.KeyID)
			if err != nil {
				b.Logger().Warn("failed to remove new password for role", "role", roleName, "error", err)
			}
			return fmt.Errorf("failed to save role %q: %w", roleName, err)
		}
		b.Logger().Debug("updated role credentials", "role", roleName)

		// remove all expired passwords
		now := time.Now()
		for _, pw := range servicePrincipal.PasswordCredentials {
			if pw.EndDate.Before(now) {
				err = client.removeSPPassword(ctx, role.ServicePrincipalID, *pw.KeyID)
				if err != nil {
					b.Logger().Warn("failed to remove old password for role", "role", roleName, "error", err)
				}
			}
		}
	}

	return nil
}

func findPasswordWithID(keyID string, passwords []api.PasswordCredential) (api.PasswordCredential, bool) {
	for _, password := range passwords {
		if *password.KeyID == keyID {
			return password, true
		}
	}
	return api.PasswordCredential{}, false
}

// reset clears the backend's cached client
// This is used when the configuration changes and a new client should be
// created with the updated settings.
func (b *azureSecretBackend) reset() {
	b.lock.Lock()
	defer b.lock.Unlock()

	b.settings = nil
	b.client = nil
}

func (b *azureSecretBackend) invalidate(ctx context.Context, key string) {
	switch key {
	case "config":
		b.reset()
	}
}

func (b *azureSecretBackend) getClient(ctx context.Context, s logical.Storage) (*client, error) {
	b.lock.RLock()

	if b.client.Valid() {
		b.lock.RUnlock()
		return b.client, nil
	}

	b.lock.RUnlock()
	b.lock.Lock()
	defer b.lock.Unlock()

	if b.client.Valid() {
		return b.client, nil
	}

	config, err := b.getConfig(ctx, s)
	if err != nil {
		return nil, err
	}

	if b.settings == nil {
		if config == nil {
			config = new(azureConfig)
		}

		settings, err := b.getClientSettings(ctx, config)
		if err != nil {
			return nil, err
		}
		b.settings = settings
	}

	if config == nil {
		return nil, fmt.Errorf("config is nil")
	}

	passwords := api.Passwords{
		PolicyGenerator: b.System(),
		PolicyName:      config.PasswordPolicy,
	}

	p, err := b.getProvider(b.settings, passwords)
	if err != nil {
		return nil, err
	}

	c := &client{
		provider:   p,
		settings:   b.settings,
		expiration: time.Now().Add(clientLifetime),
		passwords:  passwords,
	}
	b.client = c

	return c, nil
}

const backendHelp = `
The Azure secrets backend dynamically generates Azure service
principals. The SP credentials have a configurable lease and
are automatically revoked at the end of the lease.

After mounting this backend, credentials to manage Azure resources
must be configured with the "config/" endpoints and policies must be
written using the "roles/" endpoints before any credentials can be
generated.
`
