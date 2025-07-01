# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a JWT/JWE proof-of-concept Spring Boot application that demonstrates JWT token creation, validation, and JWE encryption/decryption workflows. The application integrates with Auth0 for token validation in production scenarios while also supporting local JWT token generation for testing.

**Token Flow**: JWT -> JWS -> JWE -> validated JWS

## JWE Support
- **Token Detection**: Automatic detection of JWE tokens (5 parts) vs JWT tokens (3 parts)
- **Algorithm Support**: dir (Direct Key Agreement) with A256GCM encryption
- **JWE Processing**: Uses Nimbus JOSE+JWT library for JWE decryption
- **Configuration**: Supports configurable 256-bit shared secret via `jwe.shared-secret`
- **Production Ready**: Environment variable support for secure key management
- **Debug Endpoints**: `/jwe/status` and `/jwe/help` provide configuration guidance

## Architecture

- **Framework**: Spring Boot 3.1.3 with Java 17
- **Security**: JWT tokens with RSA256 signing, Auth0 integration
- **Protocol**: HTTPS with self-signed certificate (port 8443)
- **Structure**: Standard Spring Boot layered architecture
  - Controllers: Handle HTTP endpoints for authentication and services
  - Services: Core JWT processing logic
  - Resources: Configuration and SSL keystore

## Key Components

### Core Services
- `JwtService` (src/main/java/com/example/demo/services/JwtService.java): Handles JWT creation, validation, Auth0 integration, and custom API token validation

### Controllers
- `AuthenticationController`: Manages login, public key retrieval, and SSO signin
- `ApiTokenController`: Creates machine-to-machine API tokens from user login sessions
- `JweConfigController`: Provides JWE configuration status and help endpoints
- `ServiceAController` & `ServiceBController`: Protected service endpoints requiring JWT authentication

### Security Filter
- `JwtAuthenticationFilter`: Servlet filter that validates bearer tokens for all API endpoints

### Configuration
- SSL/HTTPS enabled by default on port 8443
- JKS keystore: `src/main/resources/keystore/springboot.jks`
- Auth0 integration: `https://sonatype-mtiq-test.us.auth0.com/`

## Development Commands

### Build and Test
```bash
# Clean build and run tests
./mvnw clean test

# Run application (HTTPS on port 8443)
./mvnw spring-boot:run

# Build without tests
./mvnw clean compile

# Package application
./mvnw clean package
```

### JWE Configuration
```bash
# Set JWE shared secret for development
export JWE_SHARED_SECRET="your-256-bit-secret-key-here-32"

# Check JWE status
curl -k https://localhost:8443/jwe/status

# Get JWE help
curl -k https://localhost:8443/jwe/help
```

### Testing Individual Components
```bash
# Run specific test class
./mvnw test -Dtest=JwtServiceTest

# Run with debugging
./mvnw test -Dmaven.surefire.debug
```

## Authentication Flow

1. **SSO Login**: User authenticates via Auth0 in web interface
2. **API Token Creation**: POST to `/api/tokens/create` with Auth0 token creates custom API token
3. **Token Validation**: Both Auth0 and custom API tokens validated by `JwtService`
4. **Service Access**: Protected endpoints require valid JWT in Authorization header

### Token Types
- **Auth0 Tokens**: Short-lived tokens from SSO login (used for web interface)
- **API Tokens**: Long-lived custom tokens (30 days) for machine-to-machine access

### Test Users (for legacy `/login` endpoint)
- `serviceA`: password `69605c3eba8141ffa85ec07fa5d37886`  
- `serviceB`: password `0ec0448ee4ea49248ddd51e85376df64`

## SSL Configuration

Application runs on HTTPS by default:
- Port: 8443
- Keystore: JKS format in `src/main/resources/keystore/springboot.jks`
- Password: `password`
- Alias: `springboot`

## Dependencies

Key libraries:
- `com.auth0:java-jwt:4.0.0` - JWT processing
- `com.auth0:jwks-rsa:0.22.1` - Auth0 JWKS integration  
- `com.nimbusds:nimbus-jose-jwt:9.37.3` - JWE encryption/decryption
- `org.apache.httpcomponents:httpclient:4.5.14` - HTTP client
- `com.google.code.gson:2.10.1` - JSON processing

## Important Notes

- The application uses Auth0 for production JWT validation but includes local key generation for development
- All endpoints except `/login`, `/publickey`, and `/signin` require JWT authentication
- Private keys are embedded in code for demo purposes only - not suitable for production
- SSL certificate is self-signed for development only