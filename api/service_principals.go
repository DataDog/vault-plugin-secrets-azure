package api

import (
	"context"
	"time"
)

type ServicePrincipalClient interface {
	// CreateServicePrincipal in Azure. The password returned is the actual password that the appID was created with
	CreateServicePrincipal(ctx context.Context, appID string, startDate time.Time, endDate time.Time) (id string, password PasswordCredential, err error)
	DeleteServicePrincipal(ctx context.Context, spObjectID string, permanentlyDelete bool) error
	GetServicePrincipal(ctx context.Context, spID string) (ServicePrincipalDetails, error)

	RemovePasswordForServicePrincipal(ctx context.Context, spID, keyID string) error
	AddPasswordForServicePrincipal(ctx context.Context, spID string, startDate time.Time, endDate time.Time) (PasswordCredential, error)
}

type ServicePrincipal struct {
	ObjectID string
	AppID    string
}
