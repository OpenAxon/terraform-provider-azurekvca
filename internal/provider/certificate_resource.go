package provider

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"math/big"
	"slices"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azcertificates"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64default"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/objectplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ resource.Resource              = &certificateResource{}
	_ resource.ResourceWithConfigure = &certificateResource{}
)

func NewCertificateResource() resource.Resource {
	return &certificateResource{}
}

type certificateResourceModel struct {
	Name              types.String      `tfsdk:"name"`
	CAName            types.String      `tfsdk:"ca_name"`
	Trigger           types.String      `tfsdk:"trigger"`
	VaultURL          types.String      `tfsdk:"vault_url"`
	CertificatePolicy CertificatePolicy `tfsdk:"certificate_policy"`
}

type certificateResource struct {
	azureCred *azcore.TokenCredential
}

type CertificatePolicy struct {
	CertificateKeyProperties  CertificateKeyProperties  `tfsdk:"key_properties"`
	SecretProperties          SecretProperties          `tfsdk:"secret_properties"`
	X509CertificateProperties X509CertificateProperties `tfsdk:"x509_certificate_properties"`
}

type CertificateKeyProperties struct {
	Curve      types.String `tfsdk:"curve"`
	Exportable types.Bool   `tfsdk:"exportable"`
	KeySize    types.Int64  `tfsdk:"key_size"`
	KeyType    types.String `tfsdk:"key_type"`
	ReuseKey   types.Bool   `tfsdk:"reuse_key"`
}

type SecretProperties struct {
	ContentType types.String `tfsdk:"content_type"`
}

type X509CertificateProperties struct {
	Subject                 types.String            `tfsdk:"subject"`
	KeyUsage                []string                `tfsdk:"key_usage"`
	ExtendedKeyUsage        []string                `tfsdk:"extended_key_usage"`
	ValidityInMonths        types.Int64             `tfsdk:"validity_in_months"`
	SubjectAlternativeNames SubjectAlternativeNames `tfsdk:"subject_alternative_names"`
}

type SubjectAlternativeNames struct {
	DNSNames []string `tfsdk:"dns_names"`
	Emails   []string `tfsdk:"emails"`
	UPNs     []string `tfsdk:"upns"`
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
			"name": schema.StringAttribute{
				MarkdownDescription: "Name of certificate to create",
				Required:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"ca_name": schema.StringAttribute{
				MarkdownDescription: "Name of CA to use for signing",
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
				MarkdownDescription: "URL of Azure Key Vault where the certificate will be created",
				Required:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"certificate_policy": schema.SingleNestedAttribute{
				MarkdownDescription: "Certificate policy",
				Required:            true,
				Attributes: map[string]schema.Attribute{
					"key_properties": schema.SingleNestedAttribute{
						MarkdownDescription: "Private key attributes",
						Required:            true,
						Attributes: map[string]schema.Attribute{
							"curve": schema.StringAttribute{
								MarkdownDescription: "One of (P-256, P-384, P-521). Required if key type is EC or EC-HSM",
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
					"secret_properties": schema.SingleNestedAttribute{
						MarkdownDescription: "Secret properties",
						Optional:            true,
						Attributes: map[string]schema.Attribute{
							"content_type": schema.StringAttribute{
								MarkdownDescription: "Content type of the secret",
								Optional:            true,
								Computed:            true,
								Default:             stringdefault.StaticString("application/x-pem-file"),
							},
						},
					},
					"x509_certificate_properties": schema.SingleNestedAttribute{
						MarkdownDescription: "X.509 certificate properties",
						Required:            true,
						Attributes: map[string]schema.Attribute{
							"subject": schema.StringAttribute{
								MarkdownDescription: "Subject name of the certificate",
								Required:            true,
							},
							"key_usage": schema.ListAttribute{
								MarkdownDescription: "Key usage of the certificate",
								Required:            true,
								ElementType:         types.StringType,
							},
							"extended_key_usage": schema.ListAttribute{
								MarkdownDescription: "Extended key usage of the certificate",
								Optional:            true,
								ElementType:         types.StringType,
							},
							"validity_in_months": schema.Int64Attribute{
								MarkdownDescription: "Validity period of the certificate in months",
								Optional:            true,
								Computed:            true,
								Default:             int64default.StaticInt64(1),
							},
							"subject_alternative_names": schema.SingleNestedAttribute{
								MarkdownDescription: "Subject alternative names for the certificate",
								Optional:            true,
								Attributes: map[string]schema.Attribute{
									"dns_names": schema.ListAttribute{
										MarkdownDescription: "DNS names for the certificate",
										Optional:            true,
										ElementType:         types.StringType,
									},
									"emails": schema.ListAttribute{
										MarkdownDescription: "Email addresses for the certificate",
										Optional:            true,
										ElementType:         types.StringType,
									},
									"upns": schema.ListAttribute{
										MarkdownDescription: "User Principal Names for the certificate",
										Optional:            true,
										ElementType:         types.StringType,
									},
								},
							},
						},
					},
				},
			},
		},
	}
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
			"Error creating azcertificates client",
			"Could not create azcertificates client, unexpected error: "+err.Error(),
		)
		return
	}

	keySize := int32(plan.CertificatePolicy.CertificateKeyProperties.KeySize.ValueInt64())
	issuer := "Unknown"
	contentType := string(plan.CertificatePolicy.SecretProperties.ContentType.ValueString())
	subject := string(plan.CertificatePolicy.X509CertificateProperties.Subject.ValueString())

	keyUsage := []*azcertificates.KeyUsageType{}
	for _, usage := range plan.CertificatePolicy.X509CertificateProperties.KeyUsage {
		keyUsage = append(keyUsage, toKeyUsageType(ParseKeyUsageType(usage)))
	}

	azureCertParams := azcertificates.CreateCertificateParameters{
		CertificatePolicy: &azcertificates.CertificatePolicy{
			IssuerParameters: &azcertificates.IssuerParameters{
				Name: &issuer,
			},
			KeyProperties: &azcertificates.KeyProperties{
				Curve:      (*azcertificates.CurveName)(plan.CertificatePolicy.CertificateKeyProperties.Curve.ValueStringPointer()),
				Exportable: plan.CertificatePolicy.CertificateKeyProperties.Exportable.ValueBoolPointer(),
				KeySize:    &keySize,
				KeyType:    (*azcertificates.KeyType)(plan.CertificatePolicy.CertificateKeyProperties.KeyType.ValueStringPointer()),
				ReuseKey:   plan.CertificatePolicy.CertificateKeyProperties.ReuseKey.ValueBoolPointer(),
			},
			SecretProperties: &azcertificates.SecretProperties{
				ContentType: &contentType,
			},
			X509CertificateProperties: &azcertificates.X509CertificateProperties{
				Subject:  &subject,
				KeyUsage: keyUsage,
			},
		},
	}

	if len(plan.CertificatePolicy.X509CertificateProperties.SubjectAlternativeNames.DNSNames) > 0 {
		azureCertParams.CertificatePolicy.X509CertificateProperties.SubjectAlternativeNames = &azcertificates.SubjectAlternativeNames{
			DNSNames:           []*string{},
			Emails:             []*string{},
			UserPrincipalNames: []*string{},
		}
		for _, dnsName := range plan.CertificatePolicy.X509CertificateProperties.SubjectAlternativeNames.DNSNames {
			azureCertParams.CertificatePolicy.X509CertificateProperties.SubjectAlternativeNames.DNSNames = append(azureCertParams.CertificatePolicy.X509CertificateProperties.SubjectAlternativeNames.DNSNames, &dnsName)
		}

		for _, email := range plan.CertificatePolicy.X509CertificateProperties.SubjectAlternativeNames.Emails {
			azureCertParams.CertificatePolicy.X509CertificateProperties.SubjectAlternativeNames.Emails = append(azureCertParams.CertificatePolicy.X509CertificateProperties.SubjectAlternativeNames.Emails, &email)
		}

		for _, upn := range plan.CertificatePolicy.X509CertificateProperties.SubjectAlternativeNames.UPNs {
			azureCertParams.CertificatePolicy.X509CertificateProperties.SubjectAlternativeNames.UserPrincipalNames = append(azureCertParams.CertificatePolicy.X509CertificateProperties.SubjectAlternativeNames.UserPrincipalNames, &upn)
		}
	}

	certResp, err := certClient.CreateCertificate(ctx, plan.Name.ValueString(), azureCertParams, nil)

	if err != nil {
		resp.Diagnostics.AddError(
			"Error creating cert",
			"Could not create cert, unexpected error: "+err.Error(),
		)
		return
	}

	csr, err := x509.ParseCertificateRequest(certResp.CSR)

	caCert, err := certClient.GetCertificate(ctx, plan.CAName.ValueString(), "", nil)

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
		ExtKeyUsage:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		ExtraExtensions: []pkix.Extension{csr.Extensions[sanIdx]},
		IsCA:            false,
		NotAfter:        time.Now().Add(validityHours),
		NotBefore:       time.Now(),
		SerialNumber:    big.NewInt(time.Now().UnixMilli()),
		Subject:         csr.Subject,
		PublicKey:       csr.PublicKey,
	}

	signer, _ := NewAzureKVSigner(ctx, *r.azureCred, plan.VaultURL.ValueString(), plan.CAName.ValueString(), azkeys.SignatureAlgorithmRS256, parsedCACert.PublicKey)

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

	_, err = certClient.MergeCertificate(ctx, plan.Name.ValueString(), certParams, nil)

	if err != nil {
		resp.Diagnostics.AddError(
			"Error merging cert",
			"Could not merge cert, unexpected error: "+err.Error(),
		)
		return
	}

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
