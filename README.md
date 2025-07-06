# 🛡️ AWSForge

A modern, Enterprise-grade AWS Cognito authentication module for Node.js applications, with full support for user registration, login, confirmation, and password recovery using JWT handling.

---

## Features

1. **User Registration** with Email OTP confirmation
2. **Secure Login** with Cognito JWT tokens
3. **Forgot Password** flow
4. **Custom Attribute Validation**
5. **Extensible Configuration Presets**
6. Built with TypeScript for full type-safety
7. Ready for ESM environments (`type: "module"`)

---

## 📦 Installation

```bash
npm install awsforge
```

or

```bash
yarn add awsforge
```

---

## 📁 Project Structure

```
awsforge/
|   .gitignore
|   dev-test.js
|   dev-test.ts
|   package-lock.json
|   package.json
|   README.md
|   tsconfig.json
|
+---src
|   |   index.js
|   |   index.ts
|   |
|   +---config
|   |       packageConfig.ts
|   |
|   +---services
|   |       cognito.js
|   |       cognito.ts
|   |
|   +---types
|   |       index.js
|   |       index.ts
|   |
|   \---utils
|           tokenManager.js
|           tokenManager.ts
|
\---test
        cognito.test.ts
```
---

## ⚙️ Environment Configuration

Create a `.env` file in your root directory with the following values:

```env
AWS_REGION=us-east-1
AWS_ACCESS_KEY=YOUR_AWS_ACCESS_KEY
AWS_SECRET_KEY=YOUR_AWS_SECRET_KEY
USER_POOL_ID=YOUR_COGNITO_USER_POOL_ID
CLIENT_ID=YOUR_COGNITO_APP_CLIENT_ID
CLIENT_SECRET=YOUR_COGNITO_APP_CLIENT_SECRET  # Optional
```

These will be injected using dotenv.

---

## 🚀 Usage

### 1. Import & Initialize the Service

```typescript
import { CognitoService, CognitoConfigs } from 'awsforge';

const cognito = new CognitoService(
  CognitoConfigs.withCustomAttributes(
    {
      region: process.env.AWS_REGION!,
      userPoolId: process.env.USER_POOL_ID!,
      clientId: process.env.CLIENT_ID!,
      clientSecret: process.env.CLIENT_SECRET,
    },
    ['plan', 'role'] // Allowed custom attributes
  )
);
```

---

## CognitoService API

### `registerUser(registrationData)`

Registers a new user with AWS Cognito.

```typescript
await cognito.registerUser({
  username: 'john',
  password: 'StrongPass123!',
  email: 'john@example.com',
  firstName: 'John',
  lastName: 'Doe',
  phoneNumber: '+11234567890',
  customAttributes: {
    plan: 'pro',
    role: 'admin'
  }
});
```

**Returns:** AWS Cognito SignUpCommand response

### `confirmUserRegistration({ username, confirmationCode })`

Confirms the user using the OTP code sent to their email.

```typescript
await cognito.confirmUserRegistration({
  username: 'john@example.com',
  confirmationCode: '123456'
});
```

### `loginUser({ username, password })`

Logs in the user and returns JWT tokens.

```typescript
const loginResponse = await cognito.loginUser({
  username: 'john@example.com',
  password: 'StrongPass123!'
});
```

### `initiateForgotPassword({ username })`

Initiates forgot password process (sends reset code).

```typescript
await cognito.initiateForgotPassword({
  username: 'john@example.com'
});
```

_Note: You can later extend with confirm-reset functionality as well._

---

## Configuration Helpers

### `CognitoConfigs.minimal(baseConfig)`

Allows no custom attributes.

### `CognitoConfigs.withCustomAttributes(baseConfig, customAttributes[])`

Strictly allows only the listed custom attributes.

### `CognitoConfigs.permissive(baseConfig)`

Disables custom attribute validation altogether (⚠️ use with caution).

---

## Utility: Token Extraction

If you're using the login response and want to extract tokens:

```typescript
import { extractTokens } from 'awsforge';

const tokens = extractTokens(loginResponse);
console.log(tokens.accessToken);
```

---

## Testing Locally

Create a test file:

```typescript
import 'dotenv/config';
import { CognitoService, CognitoConfigs } from './dist';

const cognito = new CognitoService(/* config */);

await cognito.registerUser(/* user data */);
```

Run with:

```bash
npx ts-node --loader ts-node/esm dev-test.ts
```

---

## 📚 Types

Exported from `src/types/index.ts`, for usage in consumers:

- `AWSForgeConfig`
- `UserRegistrationData`
- `AuthTokens`
- `AuthResponse`
- `ResetPasswordData`

And more...

---

## NPM Publishing Notes

- This package is published with `"type": "module"`
- Only `dist/`, `README.md`, and `LICENSE` are shipped
- Written in TypeScript and compiled to ESM `.js` for use
- No runtime deps except `@aws-sdk` and `jsonwebtoken`

---

## 📄 License

MIT © 2025 Avdhut Noola

Contributions welcome via GitHub issues or pull requests.

---