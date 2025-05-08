## Contributing to go-pgmultiauth

If you find an issue with this library, please report an issue. If you'd like, we welcome any contributions. Fork this library and submit a pull request.

### Testing

The unit tests cover basic scenarios.

The `TestConnectivity` integration test validates connectivity with PostgreSQL server under various auth modes.
By default, StandardAuth is tested by creating a postgres container. `PGURL` can be passed to test against existing PostgreSQL server.

To run the integration tests for other authentication methods, the test needs to run in the appropriate environment (cloud-based auth) with the following environment variables:
- `PGURL`: PostgreSQL connection string.
- `AUTH_METHOD`: `aws`, `azure` or `gcp`
- `AWS_REGION`: Region of AWS where the database is present. Required when `AUTH_METHOD` is `aws`.
- `AZURE_CLIENT_ID`: Client ID of a user-assigned Managed Service Identity. System-assigned Managed Service Identity is used if `AZURE_CLIENT_ID` is not provided and `AUTH_METHOD` is `azure`.
