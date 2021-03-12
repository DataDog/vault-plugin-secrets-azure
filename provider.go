package azuresecrets

import (
	"context"

	"github.com/Azure/azure-sdk-for-go/services/graphrbac/1.6/graphrbac"
	"github.com/Azure/azure-sdk-for-go/services/preview/authorization/mgmt/2018-01-01-preview/authorization"
	"github.com/Azure/go-autorest/autorest"
	azureadal "github.com/Azure/go-autorest/autorest/adal"
	"github.com/Azure/go-autorest/autorest/azure/auth"
	azureauth "github.com/Azure/go-autorest/autorest/azure/auth"
	"github.com/Azure/go-autorest/autorest/date"
	"github.com/hashicorp/vault/sdk/helper/useragent"
)

// AzureProvider is an interface to access underlying Azure client objects and supporting services.
// Where practical the original function signature is preserved. client provides higher
// level operations atop AzureProvider.
type AzureProvider interface {
	ApplicationsClient
	MsGraphApplicationClient
	ServicePrincipalsClient
	ADGroupsClient
	RoleAssignmentsClient
	RoleDefinitionsClient
	AccessTokenClient
}

type MsGraphApplicationClient interface {
	AddApplicationPassword(ctx context.Context, applicationObjectID string, displayName string, endDateTime date.Time) (result PasswordCredentialResult, err error)
	RemoveApplicationPassword(background context.Context, applicationObjectID string, keyID string) (result autorest.Response, err error)
}

type ApplicationsClient interface {
	CreateApplication(ctx context.Context, parameters graphrbac.ApplicationCreateParameters) (graphrbac.Application, error)
	DeleteApplication(ctx context.Context, applicationObjectID string) (autorest.Response, error)
	GetApplication(ctx context.Context, applicationObjectID string) (graphrbac.Application, error)
}

type ServicePrincipalsClient interface {
	CreateServicePrincipal(ctx context.Context, parameters graphrbac.ServicePrincipalCreateParameters) (graphrbac.ServicePrincipal, error)
}

type ADGroupsClient interface {
	AddGroupMember(ctx context.Context, groupObjectID string, parameters graphrbac.GroupAddMemberParameters) (result autorest.Response, err error)
	RemoveGroupMember(ctx context.Context, groupObjectID, memberObjectID string) (result autorest.Response, err error)
	GetGroup(ctx context.Context, objectID string) (result graphrbac.ADGroup, err error)
	ListGroups(ctx context.Context, filter string) (result []graphrbac.ADGroup, err error)
}

type RoleAssignmentsClient interface {
	CreateRoleAssignment(
		ctx context.Context,
		scope string,
		roleAssignmentName string,
		parameters authorization.RoleAssignmentCreateParameters) (authorization.RoleAssignment, error)
	DeleteRoleAssignmentByID(ctx context.Context, roleAssignmentID string) (authorization.RoleAssignment, error)
}

type RoleDefinitionsClient interface {
	ListRoles(ctx context.Context, scope string, filter string) ([]authorization.RoleDefinition, error)
	GetRoleByID(ctx context.Context, roleID string) (result authorization.RoleDefinition, err error)
}

type AccessTokenClient interface {
	GetToken(c azureauth.ClientCredentialsConfig) (azureadal.Token, error)
}

// provider is a concrete implementation of AzureProvider. In most cases it is a simple passthrough
// to the appropriate client object. But if the response requires processing that is more practical
// at this layer, the response signature may different from the Azure signature.
type provider struct {
	settings *clientSettings

	appClient        *graphrbac.ApplicationsClient
	msGraphAppClient *MSGraphApplicationClient
	spClient         *graphrbac.ServicePrincipalsClient
	groupsClient     *graphrbac.GroupsClient
	raClient         *authorization.RoleAssignmentsClient
	rdClient         *authorization.RoleDefinitionsClient
}

// newAzureProvider creates an azureProvider, backed by Azure client objects for underlying services.
func newAzureProvider(settings *clientSettings) (AzureProvider, error) {
	// build clients that use the GraphRBAC endpoint
	graphAuthorizer, err := getAuthorizer(settings, settings.Environment.GraphEndpoint)
	if err != nil {
		return nil, err
	}

	var userAgent string
	if settings.PluginEnv != nil {
		userAgent = useragent.PluginString(settings.PluginEnv, "azure-secrets")
	} else {
		userAgent = useragent.String()
	}

	appClient := graphrbac.NewApplicationsClient(settings.TenantID)
	appClient.Authorizer = graphAuthorizer
	appClient.AddToUserAgent(userAgent)

	spClient := graphrbac.NewServicePrincipalsClient(settings.TenantID)
	spClient.Authorizer = graphAuthorizer
	spClient.AddToUserAgent(userAgent)

	groupsClient := graphrbac.NewGroupsClient(settings.TenantID)
	groupsClient.Authorizer = graphAuthorizer
	groupsClient.AddToUserAgent(userAgent)

	graphApiAuthorizer, err := getAuthorizer(settings, defaultGraphMicrosoftComURI)
	if err != nil {
		return nil, err
	}

	msGraphAppClient := newMSGraphApplicationClient(settings.SubscriptionID)
	msGraphAppClient.Authorizer = graphApiAuthorizer
	msGraphAppClient.AddToUserAgent(userAgent)

	// build clients that use the Resource Manager endpoint
	resourceManagerAuthorizer, err := getAuthorizer(settings, settings.Environment.ResourceManagerEndpoint)
	if err != nil {
		return nil, err
	}

	raClient := authorization.NewRoleAssignmentsClient(settings.SubscriptionID)
	raClient.Authorizer = resourceManagerAuthorizer
	raClient.AddToUserAgent(userAgent)

	rdClient := authorization.NewRoleDefinitionsClient(settings.SubscriptionID)
	rdClient.Authorizer = resourceManagerAuthorizer
	rdClient.AddToUserAgent(userAgent)

	p := &provider{
		settings: settings,

		appClient:        &appClient,
		msGraphAppClient: &msGraphAppClient,
		spClient:         &spClient,
		groupsClient:     &groupsClient,
		raClient:         &raClient,
		rdClient:         &rdClient,
	}

	return p, nil
}

// getAuthorizer attempts to create an authorizer, preferring ClientID/Secret if present,
// and falling back to MSI if not.
func getAuthorizer(settings *clientSettings, resource string) (authorizer autorest.Authorizer, err error) {

	if settings.ClientID != "" && settings.ClientSecret != "" && settings.TenantID != "" {
		config := auth.NewClientCredentialsConfig(settings.ClientID, settings.ClientSecret, settings.TenantID)
		config.AADEndpoint = settings.Environment.ActiveDirectoryEndpoint
		config.Resource = resource
		authorizer, err = config.Authorizer()
		if err != nil {
			return nil, err
		}
	} else {
		config := auth.NewMSIConfig()
		config.Resource = resource
		authorizer, err = config.Authorizer()
		if err != nil {
			return nil, err
		}
	}

	return authorizer, nil
}

// CreateApplication create a new Azure application object.
func (p *provider) CreateApplication(ctx context.Context, parameters graphrbac.ApplicationCreateParameters) (graphrbac.Application, error) {
	return p.appClient.Create(ctx, parameters)
}

func (p *provider) GetApplication(ctx context.Context, applicationObjectID string) (graphrbac.Application, error) {
	return p.appClient.Get(ctx, applicationObjectID)
}

// DeleteApplication deletes an Azure application object.
// This will in turn remove the service principal (but not the role assignments).
func (p *provider) DeleteApplication(ctx context.Context, applicationObjectID string) (autorest.Response, error) {
	return p.appClient.Delete(ctx, applicationObjectID)
}

// CreateServicePrincipal creates a new Azure service principal.
// An Application must be created prior to calling this and pass in parameters.
func (p *provider) CreateServicePrincipal(ctx context.Context, parameters graphrbac.ServicePrincipalCreateParameters) (graphrbac.ServicePrincipal, error) {
	return p.spClient.Create(ctx, parameters)
}

// ListRoles like all Azure roles with a scope (often subscription).
func (p *provider) ListRoles(ctx context.Context, scope string, filter string) (result []authorization.RoleDefinition, err error) {
	page, err := p.rdClient.List(ctx, scope, filter)

	if err != nil {
		return nil, err
	}

	return page.Values(), nil
}

// GetRoleByID fetches the full role definition given a roleID.
func (p *provider) GetRoleByID(ctx context.Context, roleID string) (result authorization.RoleDefinition, err error) {
	return p.rdClient.GetByID(ctx, roleID)
}

// CreateRoleAssignment assigns a role to a service principal.
func (p *provider) CreateRoleAssignment(ctx context.Context, scope string, roleAssignmentName string, parameters authorization.RoleAssignmentCreateParameters) (authorization.RoleAssignment, error) {
	return p.raClient.Create(ctx, scope, roleAssignmentName, parameters)
}

// GetRoleAssignmentByID fetches the full role assignment info given a roleAssignmentID.
func (p *provider) GetRoleAssignmentByID(ctx context.Context, roleAssignmentID string) (result authorization.RoleAssignment, err error) {
	return p.raClient.GetByID(ctx, roleAssignmentID)
}

// DeleteRoleAssignmentByID deletes a role assignment.
func (p *provider) DeleteRoleAssignmentByID(ctx context.Context, roleAssignmentID string) (result authorization.RoleAssignment, err error) {
	return p.raClient.DeleteByID(ctx, roleAssignmentID)
}

// ListRoleAssignments lists all role assignments.
// There is no need for paging; the caller only cares about the the first match and whether
// there are 0, 1 or >1 items. Unpacking here is a simpler interface.
func (p *provider) ListRoleAssignments(ctx context.Context, filter string) ([]authorization.RoleAssignment, error) {
	page, err := p.raClient.List(ctx, filter)

	if err != nil {
		return nil, err
	}

	return page.Values(), nil
}

// AddGroupMember adds a member to a AAD Group.
func (p *provider) AddGroupMember(ctx context.Context, groupObjectID string, parameters graphrbac.GroupAddMemberParameters) (result autorest.Response, err error) {
	return p.groupsClient.AddMember(ctx, groupObjectID, parameters)
}

// RemoveGroupMember removes a member from a AAD Group.
func (p *provider) RemoveGroupMember(ctx context.Context, groupObjectID, memberObjectID string) (result autorest.Response, err error) {
	return p.groupsClient.RemoveMember(ctx, groupObjectID, memberObjectID)
}

// GetGroup gets group information from the directory.
func (p *provider) GetGroup(ctx context.Context, objectID string) (result graphrbac.ADGroup, err error) {
	return p.groupsClient.Get(ctx, objectID)
}

// ListGroups gets list of groups for the current tenant.
func (p *provider) ListGroups(ctx context.Context, filter string) (result []graphrbac.ADGroup, err error) {
	page, err := p.groupsClient.List(ctx, filter)
	if err != nil {
		return nil, err
	}

	return page.Values(), nil
}

// GetToken fetches a new Azure OAuth2 bearer token from the given clients
// credentials and tenant.
func (p *provider) GetToken(c azureauth.ClientCredentialsConfig) (azureadal.Token, error) {
	t, err := c.ServicePrincipalToken()
	if err != nil {
		return azureadal.Token{}, err
	}

	err = t.Refresh()
	if err != nil {
		return azureadal.Token{}, err
	}

	return t.Token(), nil
}

func (p *provider) AddApplicationPassword(ctx context.Context, applicationObjectID string, displayName string, endDateTime date.Time) (result PasswordCredentialResult, err error) {
	req, err := p.msGraphAppClient.addPasswordPreparer(ctx, applicationObjectID, displayName, endDateTime)
	if err != nil {
		err = autorest.NewErrorWithError(err, "provider", "AddApplicationPassword", nil, "Failure preparing request")
		return
	}

	resp, err := p.msGraphAppClient.addPasswordSender(req)
	if err != nil {
		result.Response = autorest.Response{Response: resp}
		err = autorest.NewErrorWithError(err, "provider", "AddApplicationPassword", resp, "Failure sending request")
		return
	}

	result, err = p.msGraphAppClient.addPasswordResponder(resp)
	if err != nil {
		err = autorest.NewErrorWithError(err, "provider", "AddApplicationPassword", resp, "Failure responding to request")
	}

	return
}

func (p *provider) RemoveApplicationPassword(ctx context.Context, applicationObjectID string, keyID string) (result autorest.Response, err error) {
	req, err := p.msGraphAppClient.removePasswordPreparer(ctx, applicationObjectID, keyID)
	if err != nil {
		err = autorest.NewErrorWithError(err, "provider", "RemoveApplicationPassword", nil, "Failure preparing request")
		return
	}

	resp, err := p.msGraphAppClient.removePasswordSender(req)
	if err != nil {
		result.Response = resp
		err = autorest.NewErrorWithError(err, "provider", "RemoveApplicationPassword", resp, "Failure sending request")
		return
	}

	result, err = p.msGraphAppClient.removePasswordResponder(resp)
	if err != nil {
		err = autorest.NewErrorWithError(err, "provider", "RemoveApplicationPassword", resp, "Failure responding to request")
	}

	return
}
