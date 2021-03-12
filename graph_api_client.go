package azuresecrets

import (
	"context"
	"net/http"

	"github.com/Azure/azure-sdk-for-go/services/preview/authorization/mgmt/2018-01-01-preview/authorization"
	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/azure"
	"github.com/Azure/go-autorest/autorest/date"
	"github.com/Azure/go-autorest/autorest/to"
)

const (
	// defaultGraphMicrosoftComURI is the default URI used for the service MS Graph API
	defaultGraphMicrosoftComURI = "https://graph.microsoft.com"
)

type MSGraphApplicationClient struct {
	authorization.BaseClient
}

func newMSGraphApplicationClient(subscriptionId string) MSGraphApplicationClient {
	return MSGraphApplicationClient{authorization.NewWithBaseURI(defaultGraphMicrosoftComURI, subscriptionId)}
}

func (client MSGraphApplicationClient) addPasswordPreparer(ctx context.Context, applicationObjectID string, displayName string, endDateTime date.Time) (*http.Request, error) {
	pathParameters := map[string]interface{}{
		"applicationObjectId": autorest.Encode("path", applicationObjectID),
	}

	parameters := struct {
		PasswordCredential *passwordCredential `json:"passwordCredential"`
	}{
		PasswordCredential: &passwordCredential{
			DisplayName: to.StringPtr(displayName),
			EndDate:     &endDateTime,
		},
	}

	preparer := autorest.CreatePreparer(
		autorest.AsContentType("application/json; charset=utf-8"),
		autorest.AsPost(),
		autorest.WithBaseURL(client.BaseURI),
		autorest.WithPathParameters("/v1.0/applications/{applicationObjectId}/addPassword", pathParameters),
		autorest.WithJSON(parameters),
		client.Authorizer.WithAuthorization())
	return preparer.Prepare((&http.Request{}).WithContext(ctx))
}

func (client MSGraphApplicationClient) addPasswordSender(req *http.Request) (*http.Response, error) {
	sd := autorest.GetSendDecorators(req.Context(), autorest.DoRetryForStatusCodes(client.RetryAttempts, client.RetryDuration, autorest.StatusCodesForRetry...))
	return autorest.SendWithSender(client, req, sd...)
}

func (client MSGraphApplicationClient) addPasswordResponder(resp *http.Response) (result PasswordCredentialResult, err error) {
	err = autorest.Respond(
		resp,
		client.ByInspecting(),
		azure.WithErrorUnlessStatusCode(http.StatusOK),
		autorest.ByUnmarshallingJSON(&result),
		autorest.ByClosing())
	result.Response = autorest.Response{Response: resp}
	return
}

func (client MSGraphApplicationClient) removePasswordPreparer(ctx context.Context, applicationObjectID string, keyID string) (*http.Request, error) {
	pathParameters := map[string]interface{}{
		"applicationObjectId": autorest.Encode("path", applicationObjectID),
	}

	parameters := struct {
		KeyID string `json:"keyId"`
	}{
		KeyID: keyID,
	}

	preparer := autorest.CreatePreparer(
		autorest.AsContentType("application/json; charset=utf-8"),
		autorest.AsPost(),
		autorest.WithBaseURL(client.BaseURI),
		autorest.WithPathParameters("/v1.0/applications/{applicationObjectId}/removePassword", pathParameters),
		autorest.WithJSON(parameters),
		client.Authorizer.WithAuthorization())
	return preparer.Prepare((&http.Request{}).WithContext(ctx))
}

func (client MSGraphApplicationClient) removePasswordSender(req *http.Request) (*http.Response, error) {
	sd := autorest.GetSendDecorators(req.Context(), autorest.DoRetryForStatusCodes(client.RetryAttempts, client.RetryDuration, autorest.StatusCodesForRetry...))
	return autorest.SendWithSender(client, req, sd...)
}

func (client MSGraphApplicationClient) removePasswordResponder(resp *http.Response) (result autorest.Response, err error) {
	err = autorest.Respond(
		resp,
		client.ByInspecting(),
		azure.WithErrorUnlessStatusCode(http.StatusNoContent),
		autorest.ByUnmarshallingJSON(&result),
		autorest.ByClosing())
	result.Response = resp
	return
}

type passwordCredential struct {
	DisplayName *string `json:"displayName"`
	// StartDate - Start date.
	StartDate *date.Time `json:"startDateTime,omitempty"`
	// EndDate - End date.
	EndDate *date.Time `json:"endDateTime,omitempty"`
	// KeyID - Key ID.
	KeyID *string `json:"keyId,omitempty"`
	// Value - Key value.
	SecretText *string `json:"secretText,omitempty"`
}

type PasswordCredentialResult struct {
	autorest.Response `json:"-"`

	passwordCredential
}
