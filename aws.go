package pgmultiauth

import (
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/rds/rdsutils"
)

type awsTokenConfig struct {
	host     string
	port     uint16
	dbRegion string
	user     string
}

func getAWSAuthToken(config awsTokenConfig) (*authToken, error) {
	token, err := fetchAWSAuthToken(config)
	if err != nil {
		return nil, fmt.Errorf("fetching aws token: %v", err)
	}

	// The token is valid for 15 minutes, so we set the expiry time to 14 minutes
	// to account for network delays
	expiry := time.Now().Add(14 * time.Minute)
	validFn := func() bool { return time.Now().Before(expiry) }

	return &authToken{token: token, valid: validFn}, nil
}

func fetchAWSAuthToken(config awsTokenConfig) (string, error) {
	awsConfig := &aws.Config{
		Region: aws.String(config.dbRegion),
	}

	sess, err := session.NewSession(awsConfig)
	if err != nil {
		return "", err
	}

	creds := sess.Config.Credentials

	authToken, err := rdsutils.BuildAuthToken(
		fmt.Sprintf("%s:%d", config.host, config.port),
		config.dbRegion,
		config.user,
		creds,
	)
	if err != nil {
		return "", err
	}

	return authToken, nil
}
