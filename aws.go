package pgmultiauth

import (
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/rds/rdsutils"
)

type awsTokenConfig struct {
	host      string
	port      uint16
	user      string
	awsConfig *aws.Config
}

func (c awsTokenConfig) generateToken() (*authToken, error) {
	token, err := c.fetchAWSAuthToken()
	if err != nil {
		return nil, fmt.Errorf("fetching aws token: %v", err)
	}

	// The token is valid for 15 minutes, so we set the expiry time to 14 minutes
	// to account for network delays
	expiry := time.Now().Add(14 * time.Minute)
	validFn := func() bool { return time.Now().Before(expiry) }

	return &authToken{token: token, valid: validFn}, nil
}

func (c awsTokenConfig) fetchAWSAuthToken() (string, error) {
	creds := c.awsConfig.Credentials
	region := *c.awsConfig.Region

	authToken, err := rdsutils.BuildAuthToken(
		fmt.Sprintf("%s:%d", c.host, c.port),
		region,
		c.user,
		creds,
	)
	if err != nil {
		return "", err
	}

	return authToken, nil
}
