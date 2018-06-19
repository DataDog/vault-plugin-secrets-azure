package azuresecrets

import (
	"context"

	"github.com/Azure/azure-sdk-for-go/profiles/latest/compute/mgmt/compute"
	"github.com/Azure/azure-sdk-for-go/services/authorization/mgmt/2018-01-01-preview/authorization"
	"github.com/Azure/azure-sdk-for-go/services/graphrbac/1.6/graphrbac"
	"github.com/Azure/go-autorest/autorest"
	oidc "github.com/coreos/go-oidc"
)

// Provider is an interface to access underlying Azure client objects an supporting services.
// Where practical the underlying function signature is preserved. AzureClient provider higher
// level operations atop Provider.
type Provider interface {
	ApplicationsClient
	ServicePrincipalsClient
	VirtualMachinesClient
	RoleAssignmentsClient
	RoleDefinitionsClient
	TokenVerifier
}

type ApplicationsClient interface {
	CreateApplication(ctx context.Context, parameters graphrbac.ApplicationCreateParameters) (graphrbac.Application, error)
	DeleteApplication(ctx context.Context, applicationObjectID string) (autorest.Response, error)
}

type ServicePrincipalsClient interface {
	CreateServicePrincipal(ctx context.Context, parameters graphrbac.ServicePrincipalCreateParameters) (graphrbac.ServicePrincipal, error)
}

type VirtualMachinesClient interface {
	VMGet(ctx context.Context, resourceGroupName string, VMName string, expand compute.InstanceViewTypes) (compute.VirtualMachine, error)
	VMUpdate(ctx context.Context, resourceGroupName string, VMName string, parameters compute.VirtualMachineUpdate) (compute.VirtualMachinesUpdateFuture, error)
}

type RoleAssignmentsClient interface {
	CreateRoleAssignment(ctx context.Context, scope string, roleAssignmentName string, parameters authorization.RoleAssignmentCreateParameters) (authorization.RoleAssignment, error)
	DeleteRoleAssignmentByID(ctx context.Context, roleID string) (authorization.RoleAssignment, error)
}

type RoleDefinitionsClient interface {
	ListRoles(ctx context.Context, scope string, filter string) ([]authorization.RoleDefinition, error)
	GetRoleByID(ctx context.Context, roleID string) (result authorization.RoleDefinition, err error)
}

type TokenVerifier interface {
	VerifyToken(ctx context.Context, token string) (*oidc.IDToken, error)
}