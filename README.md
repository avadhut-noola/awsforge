# AWSForge

Enterprise-grade AWS Cognito authentication module for Node.js applications with TypeScript support.

## Features

- User registration with email OTP confirmation
- Secure login with Cognito JWT tokens
- Password recovery and reset flows
- Token verification and refresh
- Custom attribute validation
- User profile management
- Full TypeScript support
- ESM ready
- Multiple usage patterns (functional, class-based, service-based)

## Installation

```bash
npm install awsforge
```

## Environment Configuration

All environment variables are required for proper functionality:

```env
AWS_REGION=us-east-1
USER_POOL_ID=your_cognito_user_pool_id
CLIENT_ID=your_cognito_app_client_id
CLIENT_SECRET=your_cognito_app_client_secret
```

**Note**: AWS credentials are no longer required as direct environment variables. The library uses the standard AWS credential provider chain, which will look for credentials in the following order:
1. Environment variables (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
2. Shared credentials file (~/.aws/credentials)
3. ECS container credentials
4. EC2 instance profile credentials
5. Lambda function credentials

This enables more secure credential management and better compatibility with AWS services like Lambda.

## Usage Patterns

AWSForge offers multiple ways to use the library based on your preferences:

### 1. Functional API (Recommended)

The simplest way to get started with a functional approach:

```typescript
import createCognito from 'awsforge';

const cognito = createCognito({
  region: process.env.AWS_REGION,
  userPoolId: process.env.USER_POOL_ID,
  clientId: process.env.CLIENT_ID,
  clientSecret: process.env.CLIENT_SECRET,
});

// Quick registration
const result = await cognito.register({
  username: 'john_doe',
  password: 'SecurePassword123!',
  email: 'john@example.com',
  firstName: 'John',
  lastName: 'Doe'
});

// Quick login
const loginResult = await cognito.login({
  username: 'john@example.com',
  password: 'SecurePassword123!'
});
```

### 2. Class-based API

For a more structured approach:

```typescript
import { AWSForge } from 'awsforge';

const aws = new AWSForge({
  region: process.env.AWS_REGION,
  userPoolId: process.env.USER_POOL_ID,
  clientId: process.env.CLIENT_ID,
  clientSecret: process.env.CLIENT_SECRET,
});

// Use cognito methods
const result = await aws.cognito.register({
  username: 'john_doe',
  password: 'SecurePassword123!',
  email: 'john@example.com'
});

// Access utilities
const tokens = aws.utils.extractTokens(loginResult);
```

### 3. Service-based API (Original)

For full control and advanced configurations:

```typescript
import { CognitoService, CognitoConfigs } from 'awsforge';

// Initialize with custom attributes
const cognito = new CognitoService(
  CognitoConfigs.withCustomAttributes(
    {
      region: process.env.AWS_REGION,
      userPoolId: process.env.USER_POOL_ID,
      clientId: process.env.CLIENT_ID,
      clientSecret: process.env.CLIENT_SECRET,
    },
    ['plan', 'role'] // Allowed custom attributes
  )
);
```

## API Reference

### User Registration

Register a new user with email confirmation:

```typescript
// Functional API
const registrationResult = await cognito.register({
  username: 'john_doe',
  password: 'SecurePassword123!',
  email: 'john@example.com',
  firstName: 'John',
  lastName: 'Doe',
  phoneNumber: '+1234567890',
  customAttributes: {
    plan: 'premium',
    role: 'user'
  }
});

// Class-based API
const registrationResult = await aws.cognito.register({
  username: 'john_doe',
  password: 'SecurePassword123!',
  email: 'john@example.com',
  firstName: 'John',
  lastName: 'Doe'
});

// Service-based API
const registrationResult = await cognitoService.registerUser({
  username: 'john_doe',
  password: 'SecurePassword123!',
  email: 'john@example.com',
  firstName: 'John',
  lastName: 'Doe'
});
```

### Confirm Registration

Confirm user registration with OTP code:

```typescript
// Functional API
await cognito.confirmRegistration({
  username: 'john@example.com',
  confirmationCode: '123456'
});

// Class-based API
await aws.cognito.confirmRegistration({
  username: 'john@example.com',
  confirmationCode: '123456'
});

// Service-based API
await cognitoService.confirmUserRegistration({
  username: 'john@example.com',
  confirmationCode: '123456'
});
```

### User Login

Authenticate user and receive JWT tokens:

```typescript
// All APIs support the same login method
const loginResult = await cognito.login({
  username: 'john@example.com',
  password: 'SecurePassword123!'
});

// Access tokens from result
const { 
  AccessToken, 
  IdToken, 
  RefreshToken 
} = loginResult.AuthenticationResult;
```

### Token Verification

Verify JWT tokens:

```typescript
// Verify access token (all APIs)
const accessTokenResult = await cognito.verifyAccessToken(accessToken);
if (accessTokenResult.isValid) {
  console.log('Token is valid:', accessTokenResult.decoded);
} else {
  console.error('Token error:', accessTokenResult.error);
}

// Verify ID token
const idTokenResult = await cognito.verifyIdToken(idToken);

// Generic token verification
const tokenResult = await cognito.verifyToken(anyToken);
```

### Get User Profile

Retrieve user information using access token:

```typescript
const userProfile = await cognito.getUserFromToken(accessToken);
console.log('User:', userProfile.username);
console.log('Attributes:', userProfile.attributes);
```

### Refresh Tokens

Refresh expired access tokens:

```typescript
const refreshResult = await cognito.refreshTokens(refreshToken);
const newAccessToken = refreshResult.AuthenticationResult?.AccessToken;
```

### Password Reset

Initiate password reset flow:

```typescript
// Send reset code (functional/class API)
await cognito.forgotPassword({
  username: 'john@example.com'
});

// Service API
await cognitoService.initiateForgotPassword({
  username: 'john@example.com'
});

// Confirm new password with code (all APIs)
await cognito.confirmForgotPassword({
  username: 'john@example.com',
  confirmationCode: '123456',
  newPassword: 'NewSecurePassword123!'
});
```

### Change Password

Change password for authenticated user:

```typescript
await cognito.changePassword({
  accessToken: accessToken,
  previousPassword: 'OldPassword123!',
  proposedPassword: 'NewPassword123!'
});
```

### Additional Operations

```typescript
// Resend confirmation code
await cognito.resendConfirmationCode('john@example.com');

// Delete user account
await cognito.deleteUser(accessToken);

// Revoke token
await cognito.revokeToken(refreshToken);
```

## Configuration Options

### Functional API Configuration

```typescript
import createCognito from 'awsforge';

// Basic configuration
const cognito = createCognito({
  region: process.env.AWS_REGION,
  userPoolId: process.env.USER_POOL_ID,
  clientId: process.env.CLIENT_ID,
  clientSecret: process.env.CLIENT_SECRET,
});

// Access configuration presets
const { minimal, withCustomAttributes, permissive } = cognito.configs;
```

### Class-based API Configuration

```typescript
import { AWSForge } from 'awsforge';

const aws = new AWSForge({
  region: process.env.AWS_REGION,
  userPoolId: process.env.USER_POOL_ID,
  clientId: process.env.CLIENT_ID,
  clientSecret: process.env.CLIENT_SECRET,
});

// Access configuration presets
const configs = AWSForge.configs;
```

### Service-based API Configuration

#### Minimal Configuration
No custom attributes allowed:

```typescript
import { CognitoService, CognitoConfigs } from 'awsforge';

const cognito = new CognitoService(
  CognitoConfigs.minimal({
    region: process.env.AWS_REGION,
    userPoolId: process.env.USER_POOL_ID,
    clientId: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
  })
);
```

#### Custom Attributes
Specify allowed custom attributes:

```typescript
const cognito = new CognitoService(
  CognitoConfigs.withCustomAttributes(baseConfig, ['plan', 'role', 'department'])
);
```

#### Permissive Mode
Disable custom attribute validation (use with caution):

```typescript
const cognito = new CognitoService(
  CognitoConfigs.permissive(baseConfig)
);
```

## Token Utilities

Extract tokens from login response:

```typescript
import { extractTokens } from 'awsforge';
// or
import createCognito from 'awsforge';
const cognito = createCognito(config);

// Direct import
const tokens = extractTokens(loginResult);

// Via functional API
const tokens = cognito.utils.extractTokens(loginResult);

// Via class API
const aws = new AWSForge(config);
const tokens = aws.utils.extractTokens(loginResult);

console.log('Access Token:', tokens.accessToken);
console.log('ID Token:', tokens.idToken);
console.log('Refresh Token:', tokens.refreshToken);
```

## Import Options

### Default Import (Functional API)
```typescript
import createCognito from 'awsforge';
const cognito = createCognito(config);
```

### Named Imports
```typescript
import { AWSForge, CognitoService, CognitoConfigs, extractTokens } from 'awsforge';
```

### Mixed Imports
```typescript
import createCognito, { AWSForge, extractTokens } from 'awsforge';
```

### Type Imports
```typescript
import type {
  AWSForgeConfig,
  UserRegistrationData,
  UserLoginData,
  AuthTokens,
  AuthResponse,
  TokenVerificationResult,
  UserProfile,
  ChangePasswordData,
  ConfirmForgotPasswordData
} from 'awsforge';
```

## Error Handling

All methods throw descriptive errors. Always wrap calls in try-catch blocks:

```typescript
try {
  await cognito.register(userData);
} catch (error) {
  if (error.name === 'UsernameExistsException') {
    console.error('User already exists');
  } else if (error.name === 'InvalidParameterException') {
    console.error('Invalid parameters provided');
  } else {
    console.error('Registration failed:', error.message);
  }
}
```

## Migration Guide

### From Service-based to Functional API

**Before:**
```typescript
import { CognitoService, CognitoConfigs } from 'awsforge';
const cognito = new CognitoService(CognitoConfigs.minimal(config));
await cognito.registerUser(userData);
```

**After:**
```typescript
import createCognito from 'awsforge';
const cognito = createCognito(config);
await cognito.register(userData);
```

### From Service-based to Class-based API

**Before:**
```typescript
import { CognitoService } from 'awsforge';
const cognito = new CognitoService(config);
await cognito.registerUser(userData);
```

**After:**
```typescript
import { AWSForge } from 'awsforge';
const aws = new AWSForge(config);
await aws.cognito.register(userData);
```

## Development

Run tests locally:

```bash
npm test
```

Build the project:

```bash
npm run build
```

## License

MIT © 2025 Avdhut Noola

Contributions welcome via GitHub issues or pull requests.