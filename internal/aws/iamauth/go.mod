module github.com/open-telemetry/opentelemetry-collector-contrib/internal/aws/iamauth

go 1.25.0

require (
	github.com/aws/aws-sdk-go-v2 v1.41.10
	github.com/aws/aws-sdk-go-v2/config v1.32.21
	github.com/aws/aws-sdk-go-v2/credentials v1.19.20
	github.com/aws/aws-sdk-go-v2/feature/rds/auth v1.6.10
	github.com/aws/aws-sdk-go-v2/service/sts v1.43.0
	github.com/stretchr/testify v1.11.1
	go.uber.org/goleak v1.3.0
)

require (
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.18.26 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.4.26 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.7.26 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.4.27 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.13.10 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.13.26 // indirect
	github.com/aws/aws-sdk-go-v2/service/signin v1.1.2 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.31.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.36.3 // indirect
	github.com/aws/smithy-go v1.26.0 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
