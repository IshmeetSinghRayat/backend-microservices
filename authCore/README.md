Google Auth + Role-Based Access Control (RBAC) in .NET 9

Overview

This project implements Google Authentication with JWT-based authentication and Role-Based Access Control (RBAC) in a .NET 9 Minimal API. The system allows users to log in using Google OAuth, generates a JWT token, and supports protected API routes that require authentication.

Features

1. Google Authentication via OAuth2
2. JWT Authentication & Authorization
3. Role-Based Access Control (RBAC)
4. Secure secret key management
5. Supports both appsettings.json and environment variables for configuration
6. Minimal API implementation in .NET 9

Installation & Setup

1. Clone the Repository

git clone https://github.com/your-repo/google-auth-rbac-dotnet.git
cd google-auth-rbac-dotnet

2. Configure Google OAuth Credentials

Go to Google Developer Console

Create a new OAuth 2.0 Client ID

Set Authorized Redirect URI to:

http://localhost:5197/signin-google

Copy the Client ID and Client Secret

3. Set Environment Variables (Recommended for Security)

export JWT_SECRET_KEY="secure-secret-key"
export GOOGLE_CLIENT_ID="google-client-id"
export GOOGLE_CLIENT_SECRET="google-client-secret"

4. Run the Application

dotnet run

API Endpoints

1. Google Login

URL: GET /login-google
Description: Redirects user to Google authentication page.

curl -X GET http://localhost:5197/login-google

2. Google Callback

URL: GET /signin-google
Description: Handles Google OAuth callback, issues a JWT token.

3. Get User Profile

URL: GET /profileDescription: Returns authenticated user details.Headers:

Authorization: Bearer <JWT-TOKEN>

4. Protected API Route

URL: GET /protected-route
Description: Requires authentication via JWT token.Headers:

Authorization: Bearer <JWT-TOKEN>

Tech Stack

.NET 9 (Minimal API)

ASP.NET Core Authentication & Authorization

Google OAuth 2.0

JWT (JSON Web Token)

Role-Based Access Control (RBAC)

Project Structure

authCore/
├── Program.cs # Main application logic
├── appsettings.json # Configuration file
├── README.md # Documentation

Best Practices Implemented

Environment Variables for Secrets (No hardcoded keys)
JWT Authentication & Authorization
OAuth Security Best Practices
Minimal API for Simplicity & Performance

Next Steps

Implement RBAC with Google Groups & Claims
Store User Sessions in Redis for scalability
Build a Frontend (React/Next.js) for UI Authentication
