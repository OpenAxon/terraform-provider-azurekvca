package provider

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"slices"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azcertificates"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/objectplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ resource.Resource              = &certificateResource{}
	_ resource.ResourceWithConfigure = &certificateResource{}
)

func NewCertificateResource() resource.Resource {
	return &certificateResource{}
}

type certificateResource struct {
	azureCred *azcore.TokenCredential
}

type certificateKey struct {
	Curve      types.String `tfsdk:"curve"`
	Exportable types.Bool   `tfsdk:"exportable"`
	KeySize    types.Int64  `tfsdk:"key_size"`
	KeyType    types.String `tfsdk:"key_type"`
	ReuseKey   types.Bool   `tfsdk:"reuse_key"`
}

type certificateResourceModel struct {
	CSRPEM   types.String   `tfsdk:"csr_pem"`
	Key      certificateKey `tfsdk:"key"`
	Name     types.String   `tfsdk:"name"`
	Trigger  types.String   `tfsdk:"trigger"`
	VaultURL types.String   `tfsdk:"vault_url"`
}

// Metadata returns the resource type name.
func (r *certificateResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_certificate"
}

// Schema defines the schema for the resource.
func (r *certificateResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Create a new certificate version and if needed cert ready for signing",
		Attributes: map[string]schema.Attribute{
			"csr_pem": schema.StringAttribute{
				MarkdownDescription: "Resulting CSR in PEM format",
				Computed:            true,
			},
			"key": schema.SingleNestedAttribute{
				MarkdownDescription: "Private key attributes",
				Required:            true,
				Attributes: map[string]schema.Attribute{
					"curve": schema.StringAttribute{
						MarkdownDescription: "One of (P-256, P-384, P-521) Required if key type is EC or EC-HSM",
						Optional:            true,
					},
					"exportable": schema.BoolAttribute{
						MarkdownDescription: "Is key able to be exported. Not supported if -HSM key type is used",
						Required:            true,
					},
					"key_size": schema.Int64Attribute{
						MarkdownDescription: "Size of key in bits. Required if key type is RSA or RSA-HSM",
						Optional:            true,
					},
					"key_type": schema.StringAttribute{
						MarkdownDescription: "Type of key to create (RSA, RSA-HSM, EC, EC-HSM)",
						Required:            true,
					},
					"reuse_key": schema.BoolAttribute{
						MarkdownDescription: "Should private key be reused on subsequent versions",
						Required:            true,
					},
				},
				PlanModifiers: []planmodifier.Object{
					objectplanmodifier.RequiresReplace(),
				},
			},
			"name": schema.StringAttribute{
				MarkdownDescription: "Name of cert to create",
				Required:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"trigger": schema.StringAttribute{
				MarkdownDescription: "String value that when changed triggers a recreate. Good for triggering rotations",
				Optional:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"vault_url": schema.StringAttribute{
				MarkdownDescription: "URL of Azure Key Vault",
				Required:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
		},
	}
}

func toKeyUsageType(value azcertificates.KeyUsageType) *azcertificates.KeyUsageType {
	return &value
}

// Create creates the resource and sets the initial Terraform state.
func (r *certificateResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	// Retrieve values from plan
	var plan certificateResourceModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	certClient, err := azcertificates.NewClient(plan.VaultURL.ValueString(), *r.azureCred, nil)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error creating cert client",
			"Could not create cert client, unexpected error: "+err.Error(),
		)
		return
	}

	keySize := int32(plan.Key.KeySize.ValueInt64())
	issuer := "Unknown"
	contentType := "application/x-pem-file"
	subject := "CN=locmai.dev"

	keyUsage := []*azcertificates.KeyUsageType{
		toKeyUsageType(azcertificates.KeyUsageTypeKeyCertSign),
		toKeyUsageType(azcertificates.KeyUsageTypeDigitalSignature),
		toKeyUsageType(azcertificates.KeyUsageTypeKeyEncipherment),
		toKeyUsageType(azcertificates.KeyUsageTypeDataEncipherment),
		toKeyUsageType(azcertificates.KeyUsageTypeNonRepudiation),
		toKeyUsageType(azcertificates.KeyUsageTypeKeyAgreement),
	}

	azureCertParams := azcertificates.CreateCertificateParameters{
		CertificatePolicy: &azcertificates.CertificatePolicy{
			IssuerParameters: &azcertificates.IssuerParameters{
				Name: &issuer,
			},
			KeyProperties: &azcertificates.KeyProperties{
				Curve:      (*azcertificates.CurveName)(plan.Key.Curve.ValueStringPointer()),
				Exportable: plan.Key.Exportable.ValueBoolPointer(),
				KeySize:    &keySize,
				KeyType:    (*azcertificates.KeyType)(plan.Key.KeyType.ValueStringPointer()),
				ReuseKey:   plan.Key.ReuseKey.ValueBoolPointer(),
			},
			SecretProperties: &azcertificates.SecretProperties{
				ContentType: &contentType,
			},
			X509CertificateProperties: &azcertificates.X509CertificateProperties{
				Subject:  &subject,
				KeyUsage: keyUsage,
				SubjectAlternativeNames: &azcertificates.SubjectAlternativeNames{
					DNSNames: []*string{
						to.Ptr("locmai.dev"),
						to.Ptr("www.locmai.dev")},
				},
			},
		},
	}

	certResp, err := certClient.CreateCertificate(ctx, plan.Name.ValueString(), azureCertParams, nil)

	if err != nil {
		resp.Diagnostics.AddError(
			"Error creating cert",
			"Could not create cert, unexpected error: "+err.Error(),
		)
		return
	}

	csrPem := pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: certResp.CSR,
	}
	tflog.Info(ctx, fmt.Sprintf("csr pem: %v", string(pem.EncodeToMemory(&csrPem))))

	plan.CSRPEM = types.StringValue(string(pem.EncodeToMemory(&csrPem)))

	csr, err := x509.ParseCertificateRequest(certResp.CSR)

	caCert, err := certClient.GetCertificate(ctx, "root-ca", "", nil)
	tflog.Info(ctx, "============================================================")
	caCertPem := pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caCert.CER,
	}
	csrDebugPem := pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csr.Raw,
	}

	tflog.Info(ctx, fmt.Sprintf("ca cert: %v", string(pem.EncodeToMemory(&caCertPem))))
	tflog.Info(ctx, fmt.Sprintf("csr: %v", string(pem.EncodeToMemory(&csrDebugPem))))
	tflog.Info(ctx, "============================================================")

	if err != nil {
		resp.Diagnostics.AddError(
			"Error getting ca cert",
			"Could not get ca cert, unexpected error: "+err.Error(),
		)
		return
	}

	parsedCACert, err := x509.ParseCertificate(caCert.CER)
	sanIdx := slices.IndexFunc(csr.Extensions, func(e pkix.Extension) bool { return e.Id.Equal(oidExtensionSubjectAltName) })
	if sanIdx < 0 {
		resp.Diagnostics.AddError(
			"Error finding SAN extension in CSR",
			"Could not find SAN extension in CSR",
		)
		return
	}
	validityHours, err := time.ParseDuration(fmt.Sprintf("%s", "240h"))
	if err != nil {
		resp.Diagnostics.AddError(
			"Error calculating validity duration",
			"Could not calculate validity validation, unexpected error: "+err.Error(),
		)
		return
	}
	template := &x509.Certificate{
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		ExtraExtensions:       []pkix.Extension{csr.Extensions[sanIdx]},
		IsCA:                  false,
		NotAfter:              time.Now().Add(validityHours),
		NotBefore:             time.Now(),
		SerialNumber:          big.NewInt(time.Now().UnixMilli()),
		Subject:               csr.Subject,
		PublicKey:             csr.PublicKey,
		DNSNames:              csr.DNSNames,
		BasicConstraintsValid: true,
	}

	signer, _ := NewAzureKVSigner(ctx, *r.azureCred, plan.VaultURL.ValueString(), "root-ca", azkeys.SignatureAlgorithmRS256, parsedCACert.PublicKey)

	signedCert, err := x509.CreateCertificate(rand.Reader, template, parsedCACert, template.PublicKey, signer)

	if err != nil {
		resp.Diagnostics.AddError(
			"Error signing cert",
			"Could not sign cert, unexpected error: "+err.Error(),
		)
	}

	certBase64 := base64.StdEncoding.EncodeToString(signedCert)
	var certs = [][]byte{[]byte(certBase64)}

	certParams := azcertificates.MergeCertificateParameters{
		X509Certificates: certs,
	}

	tflog.Info(ctx, fmt.Sprintf("cert params: %v", signedCert))
	tflog.Info(ctx, fmt.Sprintf("cert params: %v", certParams.X509Certificates))

	_, err = certClient.MergeCertificate(ctx, plan.Name.ValueString(), certParams, nil)

	if err != nil {
		resp.Diagnostics.AddError(
			"Error merging cert",
			"Could not merge cert, unexpected error: "+err.Error(),
		)
		return
	}
	// _ = certResp

	// Set state to fully populated data
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Read refreshes the Terraform state with the latest data.
func (r *certificateResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *certificateResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
}

// Delete deletes the resource and removes the Terraform state on success.
func (r *certificateResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	// Retrieve values from state
	var state certificateResourceModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	certClient, err := azcertificates.NewClient(state.VaultURL.ValueString(), *r.azureCred, nil)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error creating cert client",
			"Could not create cert client, unexpected error: "+err.Error(),
		)
		return
	}

	// We don't actually care if this works or not
	certResp, err := certClient.DeleteCertificateOperation(ctx, state.Name.ValueString(), nil)
	_ = certResp
	_ = err

	// Set state to fully populated data
	diags = resp.State.Set(ctx, state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Configure adds the provider configured client to the resource.
func (r *certificateResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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
