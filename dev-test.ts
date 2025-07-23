// dev-test.ts - Debug version with detailed logging
import { CognitoService } from './src/services/cognito.js';
import dotenv from 'dotenv';
import fs from 'fs';
import { pathToFileURL } from 'url';

dotenv.config();

console.log("Current working directory:", process.cwd());
console.log("Environment check - .env exists:", fs.existsSync('.env'));

// Load environment variables
const testConfig = {
  clientId: process.env.COGNITO_CLIENT_ID!,
  clientSecret: process.env.COGNITO_CLIENT_SECRET!,
  userPoolId: process.env.COGNITO_USER_POOL_ID!,
  region: process.env.AWS_REGION || 'us-east-1',
};

console.log("Config loaded:", {
  clientId: !!testConfig.clientId,
  clientSecret: !!testConfig.clientSecret,
  userPoolId: !!testConfig.userPoolId,
  region: testConfig.region
});

// Test credentials
const testUser = {
  username: "nodetest721234567",
  password: "TempPassword123!",
  email: "avdhutnula2345678@gmail.com",
  firstName: "Test",
  lastName: "User",
  phoneNumber: "+1234567890",
  customAttributes: {}
};

const existingUser = {
  username: "avadhutn@ssktech.co.in",
  password: "Welcome@123"
};

// Global variables to store tokens for testing
let accessToken: string;
let idToken: string;
let refreshToken: string;

async function runTests() {
  console.log("Starting CognitoService Tests...\n");
  
  let cognitoService: CognitoService;
  
  // Test 1: Service Initialization
  console.log("Test 1: Service Initialization");
  try {
    cognitoService = new CognitoService({
      ...testConfig,
      allowedCustomAttributes: []
    });
    console.log("✓ CognitoService initialized successfully");
  } catch (error) {
    console.error("✗ Service initialization failed:", error);
    return;
  }
  console.log("-".repeat(50));

  // Test 2: User Registration (Skip if user exists)
  console.log("Test 2: User Registration");
  try {
    const registerResult = await cognitoService.registerUser({
      username: testUser.username,
      password: testUser.password,
      email: testUser.email,
      firstName: testUser.firstName,
      lastName: testUser.lastName,
      phoneNumber: testUser.phoneNumber,
      customAttributes: testUser.customAttributes
    });
    console.log("✓ User registration successful");
    console.log("UserSub:", registerResult.UserSub);
  } catch (error: any) {
    console.log("- Registration skipped:", error.message);
  }
  console.log("-".repeat(50));

  // Test 3: User Login (Store tokens for other tests)
  console.log("Test 3: User Login");
  try {
    const loginResult = await cognitoService.loginUser({
      username: existingUser.username,
      password: existingUser.password
    });
    
    if (loginResult.AuthenticationResult) {
      accessToken = loginResult.AuthenticationResult.AccessToken!;
      idToken = loginResult.AuthenticationResult.IdToken!;
      refreshToken = loginResult.AuthenticationResult.RefreshToken!;
      
      console.log("✓ Login successful");
      console.log("Tokens received:", {
        AccessToken: !!accessToken,
        IdToken: !!idToken,
        RefreshToken: !!refreshToken
      });
    }
  } catch (error: any) {
    console.error("✗ Login failed:", error.message);
    return; // Exit if login fails as other tests depend on tokens
  }
  console.log("-".repeat(50));

  // Test 4: Token Verification (New feature)
  console.log("Test 4: Token Verification");
  try {
    const accessTokenResult = await cognitoService.verifyAccessToken(accessToken);
    const idTokenResult = await cognitoService.verifyIdToken(idToken);
    
    console.log("✓ Access token verification:", accessTokenResult.isValid ? "Valid" : "Invalid");
    console.log("✓ ID token verification:", idTokenResult.isValid ? "Valid" : "Invalid");
    
    if (accessTokenResult.decoded) {
      console.log("Token expires at:", new Date(accessTokenResult.decoded.exp * 1000).toISOString());
      console.log("Token SUB:", accessTokenResult.decoded.sub);
    }
  } catch (error: any) {
    console.error("✗ Token verification failed:", error.message);
  }
  console.log("-".repeat(50));

  // Test 5: Get User Profile (New feature)
  console.log("Test 5: Get User Profile");
  try {
    const userProfile = await cognitoService.getUserFromToken(accessToken);
    console.log("✓ User profile retrieved");
    console.log("Username:", userProfile.username);
    console.log("SUB:", userProfile.attributes.sub);
    console.log("Attributes count:", Object.keys(userProfile.attributes).length);
  } catch (error: any) {
    console.error("✗ Get user profile failed:", error.message);
  }
  console.log("-".repeat(50));

  // Test 6: Refresh Tokens (Updated with access token)
  console.log("Test 6: Refresh Tokens");
  try {
    // Method 1: Using access token to get SUB (recommended)
    const refreshResult = await cognitoService.refreshTokens(refreshToken, undefined, accessToken);
    if (refreshResult.AuthenticationResult) {
      console.log("✓ Tokens refreshed successfully using access token");
      console.log("New tokens received:", {
        AccessToken: !!refreshResult.AuthenticationResult.AccessToken,
        IdToken: !!refreshResult.AuthenticationResult.IdToken
      });
    }
  } catch (error: any) {
    console.error("✗ Token refresh with access token failed:", error.message);
    
    // Method 2: Fallback to username method
    try {
      console.log("Trying refresh with username fallback...");
      const refreshResult2 = await cognitoService.refreshTokensWithUsername(refreshToken, existingUser.username);
      if (refreshResult2.AuthenticationResult) {
        console.log("✓ Tokens refreshed successfully using username fallback");
      }
    } catch (error2: any) {
      console.error("✗ Token refresh with username also failed:", error2.message);
    }
  }
  console.log("-".repeat(50));

  // Test 7: Forgot Password Flow
  console.log("Test 7: Forgot Password");
  try {
    const forgotResult = await cognitoService.initiateForgotPassword({
      username: existingUser.username
    });
    console.log("✓ Forgot password initiated");
    console.log("Code delivery:", forgotResult.CodeDeliveryDetails?.DeliveryMedium);
  } catch (error: any) {
    console.log("- Forgot password:", error.message);
  }
  console.log("-".repeat(50));

  // Test 8: Resend Confirmation Code (New feature)
  console.log("Test 8: Resend Confirmation Code");
  try {
    await cognitoService.resendConfirmationCode(testUser.username);
    console.log("✓ Confirmation code resent");
  } catch (error: any) {
    console.log("- Resend confirmation:", error.message);
  }
  console.log("-".repeat(50));

  // Test 9: Error Handling
  console.log("Test 9: Error Handling");
  try {
    await cognitoService.loginUser({
      username: "nonexistent@example.com",
      password: "wrongpassword"
    });
  } catch (error: any) {  
    console.log("✓ Error handling works correctly");
    console.log("Expected error:", error.message);
  }
  console.log("-".repeat(50));

  console.log("All tests completed!");
}

async function main() {
  console.log("Running CognitoService test suite\n");
  
  try {
    await runTests();
  } catch (error) {
    console.error("Fatal error:", error);
    console.error("Stack:", (error as Error).stack);
  }
}

// Execute if run directly
const currentFileUrl = import.meta.url;
const mainFileUrl = pathToFileURL(process.argv[1]).href;

if (currentFileUrl === mainFileUrl) {
  main().catch((error) => {
    console.error("Unhandled error:", error);
    process.exit(1);
  });
}