package provider

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"net/url"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/objectplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ resource.Resource              = &requestResource{}
	_ resource.ResourceWithConfigure = &requestResource{}
)

func NewRequestResource() resource.Resource {
	return &requestResource{}
}

type requestResource struct {
	azureCred *azcore.TokenCredential
}

type requestNames struct {
	Email []types.String `tfsdk:"email"`
	DNS   []types.String `tfsdk:"dns"`
	IP    []types.String `tfsdk:"ip"`
	URI   []types.String `tfsdk:"uri"`
}

type requestResourceModel struct {
	CSRPEMIn  types.String `tfsdk:"csr_pem_in"`
	CSRPEMOut types.String `tfsdk:"csr_pem_out"`
	Names     requestNames `tfsdk:"names"`
	VaultURL  types.String `tfsdk:"vault_url"`
}

// Metadata returns the resource type name.
func (r *requestResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_request"
}

// Schema defines the schema for the resource.
func (r *requestResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"csr_pem_in": schema.StringAttribute{
				Required: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"csr_pem_out": schema.StringAttribute{
				Computed: true,
			},
			"names": schema.SingleNestedAttribute{
				Required: true,
				Attributes: map[string]schema.Attribute{
					"email": schema.ListAttribute{
						ElementType: types.StringType,
						Optional:    true,
					},
					"dns": schema.ListAttribute{
						ElementType: types.StringType,
						Optional:    true,
					},
					"ip": schema.ListAttribute{
						ElementType: types.StringType,
						Optional:    true,
					},
					"uri": schema.ListAttribute{
						ElementType: types.StringType,
						Optional:    true,
					},
				},
				PlanModifiers: []planmodifier.Object{
					objectplanmodifier.RequiresReplace(),
				},
			},
			"vault_url": schema.StringAttribute{
				Required: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
		},
	}
}

// Create creates the resource and sets the initial Terraform state.
func (r *requestResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	// Retrieve values from plan
	var plan requestResourceModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	csrBlock, _ := pem.Decode([]byte(plan.CSRPEMIn.ValueString()))
	if csrBlock.Type != "CERTIFICATE REQUEST" {
		resp.Diagnostics.AddError(
			"Decoded PEM is not a CSR",
			"A CSR was not found in the provided PEM",
		)
		return
	}

	template, err := x509.ParseCertificateRequest(csrBlock.Bytes)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error decoding CSR",
			"Could not decode CSR, unexpected error: "+err.Error(),
		)
		return
	}

	if plan.Names.Email != nil {
		for i := 0; i < len(plan.Names.Email); i++ {
			template.EmailAddresses = append(template.EmailAddresses, plan.Names.Email[i].ValueString())
		}
	}

	if plan.Names.DNS != nil {
		for i := 0; i < len(plan.Names.DNS); i++ {
			template.DNSNames = append(template.DNSNames, plan.Names.DNS[i].ValueString())
		}
	}

	if plan.Names.IP != nil {
		for i := 0; i < len(plan.Names.IP); i++ {
			ip := net.ParseIP(plan.Names.IP[i].ValueString())
			if ip == nil {
				resp.Diagnostics.AddError(
					"Error parsing IP",
					"Could not parse IP: "+plan.Names.IP[i].ValueString(),
				)
				return
			}
			template.IPAddresses = append(template.IPAddresses, ip)
		}
	}

	if plan.Names.URI != nil {
		for i := 0; i < len(plan.Names.URI); i++ {
			url, err := url.Parse(plan.Names.URI[i].ValueString())
			if err != nil {
				resp.Diagnostics.AddError(
					"Error parsing URI",
					"Could not parse URI: "+err.Error(),
				)
				return
			}
			template.URIs = append(template.URIs, url)
		}
	}

	signer, err := NewAzureKVSigner(ctx, *r.azureCred, plan.VaultURL.ValueString(), "", "", template.PublicKey)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error creating signer",
			"Could not create signer, unexpected error: "+err.Error(),
		)
		return
	}

	certRequest, err := x509.CreateCertificateRequest(rand.Reader, template, signer)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error creating csr",
			"Could not create csr, unexpected error: "+err.Error(),
		)
		return
	}

	signedPem := pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: certRequest,
	}

	// Map response body to schema and populate Computed attribute values
	plan.CSRPEMOut = types.StringValue(string(pem.EncodeToMemory(&signedPem)))

	// Set state to fully populated data
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Read refreshes the Terraform state with the latest data.
func (r *requestResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *requestResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
}

// Delete deletes the resource and removes the Terraform state on success.
func (r *requestResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
}

// Configure adds the provider configured client to the resource.
func (r *requestResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	// Add a nil check when handling ProviderData because Terraform
	// sets that data after it calls the ConfigureProvider RPC.
	if req.ProviderData == nil {
		return
	}

	azureCred, ok := req.ProviderData.(azcore.TokenCredential)

	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Data Source Configure Type",
			fmt.Sprintf("Expected *azcore.TokenCredential, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)

		return
	}

	r.azureCred = &azureCred
}
