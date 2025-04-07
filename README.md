# Backend Microservices

A collection of microservices and shared libraries for authentication and authorization.

## Project Overview

This repository contains a set of microservices and shared libraries focused on authentication and authorization. The main components include:

- **AuthCore**: A .NET 9 Minimal API service implementing Google Authentication, JWT, and SpiceDB-based authorization
- **AuthLib**: A shared library containing common authentication and authorization functionality

## Architecture

The project follows a microservices architecture with the following components:

```
backend-microservices/
├── authCore/              # Authentication and Authorization Service
│   ├── Program.cs         # Main application logic
│   ├── appsettings.json   # Configuration
│   └── tests/            # Test suite
│
└── libraries/            # Shared Libraries
    └── AuthLib/         # Authentication Library
```

## Features

### AuthCore Service

- Google Authentication via OAuth2
- JWT Authentication & Authorization
- SpiceDB Integration for Fine-Grained Access Control
- Secure secret key management
- Minimal API implementation in .NET 9

### AuthLib Library

- Shared authentication logic
- Common authorization components
- Reusable security utilities

## Getting Started

### Prerequisites

- .NET 9 SDK
- Google OAuth credentials
- SpiceDB instance
- Git

### Installation

1. Clone the repository:

```bash
git clone https://github.com/your-repo/backend-microservices.git
cd backend-microservices
```

2. Configure environment variables:

```bash
export JWT_SECRET_KEY="your-secret-key"
export GOOGLE_CLIENT_ID="your-google-client-id"
export GOOGLE_CLIENT_SECRET="your-google-client-secret"
export SPICEDB_ENDPOINT="your-spicedb-endpoint"
export SPICEDB_API_TOKEN="your-spicedb-token"
```

3. Build and run the solution:

```bash
dotnet build
dotnet run --project authCore
```

## Development

### Building the Solution

```bash
dotnet build AuthMicroservices.sln
```

### Running Tests

```bash
dotnet test
```

## API Documentation

For detailed API documentation, please refer to the [AuthCore README](authCore/README.md).

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Google OAuth
- SpiceDB
- .NET Core
