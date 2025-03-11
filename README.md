# go-pgmultiauth-beta

pgmultiauth is a Go module that simplifies and streamlines authentication with PostgreSQL databases using multiple authentication methods. It provides a unified interface for connecting to PostgreSQL databases using various cloud authentication mechanisms.

## Features

- **Multiple Authentication Methods**: Support for AWS IAM, GCP, and Azure authentication
- **Connection Management**: Handles token refresh and reconnection logic automatically
- **Multiple consumption mechanism**: Supports various handlers like *sql.DB, driver.Connector, *pgxpool.Pool etc

## Authentication Methods

The module currently supports:

- **AWS IAM Authentication**: For RDS and Aurora PostgreSQL instances
- **GCP Authentication**: For Cloud SQL PostgreSQL instances
- **Azure Authentication**: For Azure Database for PostgreSQL

## Installation

```bash
go get github.com/hashicorp/go-pgmultiauth-beta