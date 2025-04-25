default: testacc

# TODO replace with `$(shell git describe --tags --always)` when we have tags
VERSION:=0.0.1
TERRAFORM_REGISTRY_PATH:=terraform.local
OS_ARCH:=$(shell go env GOOS)_$(shell go env GOARCH)

# Run acceptance tests
.PHONY: testacc fmt build
testacc:
	TF_ACC=1 go test ./... -v $(TESTARGS) -timeout 120m

fmt:
	@gofmt -s -w ./internal/provider/

generate-docs:
	@tfplugindocs

build: fmt
	@go build -o ./bin/terraform-provider-azurekvca
	@mkdir -p ~/.terraform.d/plugins/${TERRAFORM_REGISTRY_PATH}/local/azurekvca/${VERSION}/${OS_ARCH}
	@cp ./bin/terraform-provider-azurekvca ~/.terraform.d/plugins/${TERRAFORM_REGISTRY_PATH}/local/azurekvca/${VERSION}/${OS_ARCH}/terraform-provider-azurekvca_v${VERSION}
	@echo "Build completed successfully!"
	@echo "Module path: ~/.terraform.d/plugins/${TERRAFORM_REGISTRY_PATH}/local/azurekvca/${VERSION}/${OS_ARCH}/terraform-provider-azurekvca_v${VERSION}"

clean:
	@rm -f ./bin/terraform-provider-azurekvca
	@rm -rf ~/.terraform.d/plugins/${TERRAFORM_REGISTRY_PATH}/local/azurekvca/${VERSION}/${OS_ARCH}/terraform-provider-azurekvca_*

