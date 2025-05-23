# go-pgmultiauth

`pgmultiauth` is a Go module that simplifies and streamlines authentication with PostgreSQL databases using multiple authentication methods. It provides a unified interface for connecting to PostgreSQL databases using various authentication mechanisms.

## Features

- **Multiple Authentication Methods**: Support for AWS, GCP, and Azure authentication.
- **Connection Management**: Handles token refresh and reconnection logic automatically
- **Multiple consumption mechanism**: Supports various handlers like *sql.DB, driver.Connector, *pgxpool.Pool etc

## Authentication Methods

The module currently supports:

- **AWS  Authentication**: [For RDS and Aurora PostgreSQL instances](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.IAMDBAuth.html)
- **GCP Authentication**: [For Cloud SQL PostgreSQL instances](https://cloud.google.com/sql/docs/postgres/iam-authentication)
- **Azure Authentication**: [For Azure Database for PostgreSQL](https://learn.microsoft.com/en-us/azure/postgresql/flexible-server/how-to-connect-with-managed-identity)

## Installation

```bash
go get github.com/hashicorp/go-pgmultiauth
```


## Usage

### Using with database/sql.DB

```go

authConfig := NewConfig(
    connString,
    WithAWSConfig(awsConfig),
)

db, err := pgmultiauth.Open(ctx, authConfig)
if err != nil {
    // handle error
}
defer db.Close()

// Use db as a standard database/sql.DB
```

### Using with pgx connection pool
```go
pool, err := pgmultiauth.NewDBPool(ctx, authConfig)
if err != nil {
    // handle error
}
defer pool.Close()

// Use pool as a standard pgx.Pool
```

### Using BeforeConnect function of pgxpool.Config
```go
beforeConnect, err := pgmultiauth.BeforeConnectFn(ctx, authConfig)
if err != nil {
    // handle error
}

poolConfig := pgxpool.Config{
    ConnConfig: connConfig,
    BeforeConnect: beforeConnect,
    ..
    ..
}
```

### Using driver.Connector

```go
dbConnector, err := pgmultiauth.GetConnector(ctx, dbAuthConfig)
if err != nil {
    // handle error
}

db := sql.OpenDB(dbConnector)
```

## Contributing

Thank you for your interest in contributing! Please refer to [CONTRIBUTING.md](https://github.com/hashicorp/go-pgmultiauth/blob/main/.github/CONTRIBUTING.md)
for guidance.