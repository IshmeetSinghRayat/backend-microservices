# AuthCore - Google Auth + JWT + SpiceDB Authorization

## Overview

This project implements Google Authentication with JWT-based authentication and SpiceDB-based authorization in a .NET 9 Minimal API. The system allows users to log in using Google OAuth, generates a JWT token, and uses SpiceDB for fine-grained permission checks.

## Features

1. Google Authentication via OAuth2
2. JWT Authentication & Authorization
3. SpiceDB Integration for Fine-Grained Access Control
4. Secure secret key management
5. Supports both appsettings.json and environment variables for configuration
6. Minimal API implementation in .NET 9

## Installation & Setup

1. Clone the Repository

```bash
git clone https://github.com/your-repo/authcore.git
cd authcore
```

2. Configure Google OAuth Credentials

Go to Google Developer Console

- Create a new OAuth 2.0 Client ID
- Set Authorized Redirect URI to: `https://localhost:7197/signin-google`
- Copy the Client ID and Client Secret

3. Configure SpiceDB

- Set up a SpiceDB instance
- Get your API token and endpoint

4. Set Environment Variables (Recommended for Security)

```bash
export JWT_SECRET_KEY="secure-secret-key"
export GOOGLE_CLIENT_ID="google-client-id"
export GOOGLE_CLIENT_SECRET="google-client-secret"
export SPICEDB_ENDPOINT="your-spicedb-endpoint"
export SPICEDB_API_TOKEN="your-spicedb-token"
```

5. Run the Application

```bash
dotnet run
```

## API Endpoints

1. Google Login

URL: GET /login-google
Description: Redirects user to Google authentication page.

2. Google Callback

URL: GET /signin-google
Description: Handles Google OAuth callback, returns user claims.

3. JWT Token Generation

URL: GET /login
Description: Generates a JWT token for authenticated users.
Headers: Cookie with Google authentication

4. Permission Check

URL: GET /check-permission
Description: Checks if a user has permission for a specific resource.
Headers:

- Authorization: Bearer <JWT-TOKEN>
  Query Parameters:
- resource: The resource to check
- permission: The permission to verify

## Tech Stack

- .NET 9 (Minimal API)
- ASP.NET Core Authentication & Authorization
- Google OAuth 2.0
- JWT (JSON Web Token)
- SpiceDB for Authorization
- AuthLib (Custom Library)

## Project Structure

```
authCore/
├── Program.cs              # Main application logic
├── appsettings.json        # Configuration file
├── AuthCore.csproj         # Project dependencies
├── AuthCore.http           # API testing file
└── README.md              # Documentation
```

## Best Practices Implemented

- Environment Variables for Secrets
- JWT Authentication & Authorization
- OAuth Security Best Practices
- Minimal API for Simplicity & Performance
- SpiceDB Integration for Fine-Grained Access Control

## Next Steps

- Implement more comprehensive permission checks
- Add role-based access control using SpiceDB
- Build a Frontend (React) for UI Authentication
- Add Swagger/OpenAPI documentation
