// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/function"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
)

// Ensure azureKVCAProvider satisfies various provider interfaces.
var _ provider.Provider = &azureKVCAProvider{}
var _ provider.ProviderWithFunctions = &azureKVCAProvider{}

// azureKVCAProvider defines the provider implementation.
type azureKVCAProvider struct {
	// version is set to the provider version on release, "dev" when the
	// provider is built and ran locally, and "test" when running acceptance
	// testing.
	version string
}

// type azureKVCAProviderModel struct {
// 	TenantID    types.String `tfsdka:"tenant_id"`
// 	ClientID    types.String `tfsdka:"client_id"`
// 	Environment types.String `tfsdka:"environment"`
// }

func (p *azureKVCAProvider) Metadata(ctx context.Context, req provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "azurekvca"
	resp.Version = p.version
}

func (p *azureKVCAProvider) Schema(ctx context.Context, req provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Terraform Provider for using Azure Key Vault as a CA",
		Attributes: map[string]schema.Attribute{
			"tenant_id": schema.StringAttribute{
				Description: "The Azure tenant ID.",
				Optional:    true,
			},
			"client_id": schema.StringAttribute{
				Description: "The Azure client ID.",
				Optional:    true,
			},
			"environment": schema.StringAttribute{
				Description: "The Cloud Environment which should be used. Possible values are public, usgovernment, german, and china. Defaults to public. This can also be sourced from the ARM_ENVIRONMENT Environment Variable. Not used when metadata_host is specified.",
				Optional:    true,
			},
		},
	}
}

func (p *azureKVCAProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	// tenantID := os.Getenv("ARM_TENANT_ID")
	// clientID := os.Getenv("ARM_CLIENT_ID")
	// environment := os.Getenv("ARM_ENVIRONMENT")
	// var data azureKVCAProviderModel
	//
	// resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	//
	// if data.TenantID.ValueString() != "" {
	// 	clientID = data.TenantID.ValueString()
	// }
	//
	// if data.ClientID.ValueString() != "" {
	// 	clientID = data.ClientID.ValueString()
	// }
	//
	// if data.Environment.ValueString() != "" {
	// 	environment = data.Environment.ValueString()
	// }
	//
	// azureCredentialOptions := azidentity.DefaultAzureCredentialOptions{
	// 	TenantID: tenantID,
	// }

	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error authenticating to Azure",
			"Could not authenticate to Azure, unexpected error: "+err.Error(),
		)
		return
	}

	resp.ResourceData = cred
}

func (p *azureKVCAProvider) Resources(ctx context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewCertificateResource,

		// Deprecated resources
		NewCreateResource,
		NewRequestResource,
		NewSignResource,
		NewMergeResource,
	}
}

func (p *azureKVCAProvider) DataSources(ctx context.Context) []func() datasource.DataSource {
	return nil
}

func (p *azureKVCAProvider) Functions(ctx context.Context) []func() function.Function {
	return nil
}

func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &azureKVCAProvider{
			version: version,
		}
	}
}
