// dev-test.ts - Debug version with detailed logging
import { CognitoService } from './src/services/cognito.js';
import dotenv from 'dotenv';
import fs from 'fs';
import { pathToFileURL } from 'url';
dotenv.config();

console.log("Current working directory:", process.cwd());
console.log("Does .env exist?", fs.existsSync('.env'));
console.log("Raw .env contents:\n", fs.readFileSync('.env', 'utf8'));

// Load environment variables
console.log("Environment variables loaded successfully");
console.log("COGNITO_CLIENT_ID:", process.env.COGNITO_CLIENT_ID);

// Test configuration - Let PackageConfig handle the environment variables
const testConfig = {
  clientId: process.env.COGNITO_CLIENT_ID!,
  clientSecret: process.env.COGNITO_CLIENT_SECRET!,
  userPoolId: process.env.COGNITO_USER_POOL_ID!,
  region: process.env.AWS_REGION || 'us-east-1',
};

// Debug the configuration object
console.log("=== DEBUG CONFIG ===");
console.log("testConfig:", testConfig);
console.log("clientId exists:", !!testConfig.clientId);
console.log("clientId length:", testConfig.clientId?.length);
console.log("clientId value:", testConfig.clientId);
console.log("===================");

// ADD DEBUGGING AFTER THE CONFIG OUTPUT
console.log("\n🔍 DEBUG: About to continue with test execution...");
console.log("🔍 DEBUG: Process still running, checking next steps...");

// Test credentials
const testUser = {
  username: "nodetest7",
  password: "TempPassword123!",
  email: "avdhutnula@gmail.com",
  firstName: "Test",
  lastName: "User",
  phoneNumber: "+1234567890",
  customAttributes: {
   // You can use your own attributes only if they are configured before using in AWS Cognito
  }
};


console.log("🔍 DEBUG: Test user credentials defined");

// Existing user for login test
const existingUser = {
  username: "avadhutn@ssktech.co.in",
  password: "Welcome@123"
};

console.log("🔍 DEBUG: Existing user credentials defined");

// Add process error handlers
process.on('uncaughtException', (error) => {
  console.error('💥 UNCAUGHT EXCEPTION:', error);
  console.error('Stack:', error.stack);
  process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('💥 UNHANDLED REJECTION at:', promise);
  console.error('Reason:', reason);
  process.exit(1);
});

async function runTests() {

  console.log("🔍 DEBUG: Entering runTests function");
  
  console.log("🚀 Starting CognitoService Tests...\n");
  
  // Test 1: Configuration Test
  console.log("🔍 DEBUG: About to start Test 1 - Configuration");
  console.log("📋 Test 1: Configuration Test");
  
  let cognitoService: CognitoService;
  
  try {
    console.log("🔍 DEBUG: About to create CognitoService instance");
    console.log("Creating CognitoService with config:", testConfig);
    
    // This is likely where the error occurs
      cognitoService = new CognitoService({
        ...testConfig,
        allowedCustomAttributes: [] // <-- Add your own attributes
     });
    
    console.log("🔍 DEBUG: CognitoService instance created successfully");
    console.log("✅ CognitoService initialized successfully");
    console.log("Config:", {
      clientId: testConfig.clientId ? "✅ Set" : "❌ Missing",
      clientSecret: testConfig.clientSecret ? "✅ Set" : "❌ Missing",
      userPoolId: testConfig.userPoolId ? "✅ Set" : "❌ Missing",
      region: testConfig.region
    });
  } catch (error) {
    console.error("🔍 DEBUG: Error caught in configuration test");
    console.error("❌ Configuration failed:", error);
    console.error("Full error details:", error);
    console.error("Error stack:", (error as Error).stack);
    return; // Exit if configuration fails
  }
  
  console.log("🔍 DEBUG: Configuration test completed, continuing...");
  console.log("\n" + "=".repeat(50) + "\n");

  // Test 2: User Registration
  console.log("🔍 DEBUG: About to start Test 2 - User Registration");
  console.log("📝 Test 2: User Registration");
  try {
    console.log("🔍 DEBUG: Calling registerUser method");
    const registerResult = await cognitoService.registerUser({
      username: testUser.username,
      password: testUser.password,
      email: testUser.email,
      firstName: testUser.firstName,
      lastName: testUser.lastName,
      phoneNumber: testUser.phoneNumber,
      customAttributes: testUser.customAttributes
    });
    console.log("🔍 DEBUG: registerUser method completed");
    console.log("✅ User registration successful");
    console.log("Response:", {
      UserSub: registerResult.UserSub,
      CodeDeliveryDetails: registerResult.CodeDeliveryDetails
    });
  } catch (error: any) {
    console.log("🔍 DEBUG: Error in registration test");
    console.log("ℹ️ Registration result:", error.message);
    // This might fail if user already exists - that's okay
  }
  console.log("🔍 DEBUG: Registration test completed");
  console.log("\n" + "=".repeat(50) + "\n");

  // Test 3: Confirm Registration (Manual step required)
  console.log("🔍 DEBUG: About to start Test 3 - Confirm Registration");
  console.log("📧 Test 3: Confirm Registration");
  console.log("⚠️ Manual step required:");
  console.log("1. Check email for confirmation code");
  console.log("2. Update the confirmationCode below");
  console.log("3. Uncomment the confirmation test\n");

  // === UNCOMMENT AND UPDATE BELOW ===
  // const confirmationCode = ""; // <-- Paste the code from your email here
  // try {
  //   const confirmResult = await cognitoService.confirmUserRegistration({
  //     username: testUser.username,
  //     confirmationCode
  //   });
  //   console.log("✅ User confirmed successfully");
  //   console.log("Response:", confirmResult);
  // } catch (error: any) {
  //   console.log("❌ Confirmation failed:", error.message);
  // }

  console.log("🔄 Skipping confirmation test (requires manual code input)");
  console.log("🔍 DEBUG: Confirmation test completed (skipped)");
  console.log("\n" + "=".repeat(50) + "\n");

  // Test 4: Login with Existing User
  console.log("🔍 DEBUG: About to start Test 4 - User Login");
  console.log("🔐 Test 4: User Login (Existing User)");
  try {
    console.log("🔍 DEBUG: Calling loginUser method");
    const loginResult = await cognitoService.loginUser({
      username: existingUser.username,
      password: existingUser.password
    });
    console.log("🔍 DEBUG: loginUser method completed");
    console.log("✅ Login successful");
    console.log("Response:", {
      AccessToken: loginResult.AuthenticationResult?.AccessToken ? "✅ Present" : "❌ Missing",
      IdToken: loginResult.AuthenticationResult?.IdToken ? "✅ Present" : "❌ Missing",
      RefreshToken: loginResult.AuthenticationResult?.RefreshToken ? "✅ Present" : "❌ Missing",
      ExpiresIn: loginResult.AuthenticationResult?.ExpiresIn,
      TokenType: loginResult.AuthenticationResult?.TokenType
    });
  } catch (error: any) {
    console.error("🔍 DEBUG: Error in login test");
    console.error("❌ Login failed:", error.message);
    console.error("Error details:", error);
  }
  console.log("🔍 DEBUG: Login test completed");
  console.log("\n" + "=".repeat(50) + "\n");

  // Test 5: Forgot Password
  console.log("🔍 DEBUG: About to start Test 5 - Forgot Password");
  console.log("🔒 Test 5: Forgot Password");
  try {
    console.log("🔍 DEBUG: Calling initiateForgotPassword method");
    const forgotResult = await cognitoService.initiateForgotPassword({
      username: existingUser.username
    });
    console.log("🔍 DEBUG: initiateForgotPassword method completed");
    console.log("✅ Forgot password initiated successfully");
    console.log("Response:", {
      CodeDeliveryDetails: forgotResult.CodeDeliveryDetails
    });
  } catch (error: any) {
    console.log("🔍 DEBUG: Error in forgot password test");
    console.log("ℹ️ Forgot password result:", error.message);
  }
  console.log("🔍 DEBUG: Forgot password test completed");
  console.log("\n" + "=".repeat(50) + "\n");

  // Test 6: Error Handling
  console.log("🔍 DEBUG: About to start Test 6 - Error Handling");
  console.log("⚠️ Test 6: Error Handling");
  try {
    console.log("🔍 DEBUG: Testing error handling with invalid credentials");
    await cognitoService.loginUser({
      username: "nonexistent@example.com",
      password: "wrongpassword"
    });
  } catch (error: any) {
    console.log("🔍 DEBUG: Error handling test completed");
    console.log("✅ Error handling works correctly");
    console.log("Expected error:", error.message);
  }
  console.log("\n" + "=".repeat(50) + "\n");

  // Test 7: SECRET_HASH Verification
  console.log("🔍 DEBUG: About to start Test 7 - SECRET_HASH Verification");
  console.log("🔐 Test 7: SECRET_HASH Verification");
  try {
    console.log("🔍 DEBUG: Creating service with secret");
    const serviceWithSecret = new CognitoService(testConfig);
    console.log("✅ Service with SECRET_HASH initialized");
    
    console.log("🔍 DEBUG: Creating service without secret");
    const serviceWithoutSecret = new CognitoService({
      clientId: testConfig.clientId,
      userPoolId: testConfig.userPoolId,
      region: testConfig.region
    });
    console.log("✅ Service without SECRET_HASH initialized");
    
    console.log("🔍 Both configurations are working");
  } catch (error: any) {
    console.error("🔍 DEBUG: Error in SECRET_HASH test");
    console.error("❌ SECRET_HASH test failed:", error.message);
  }
  console.log("🔍 DEBUG: SECRET_HASH test completed");

  console.log("\n" + "🎉 All tests completed!");
  console.log("🔍 DEBUG: runTests function completed successfully");
}

// Main execution function
async function main() {
  console.log("🔍 DEBUG: Entering main function");
  console.log("Choose test mode:");
  console.log("1. Full test suite: npm run dev");
  console.log("2. Individual test: npm run dev:single\n");
  
  console.log("🔍 DEBUG: About to call runTests()");
  
  try {
    // Run full test suite
    await runTests();
    console.log("🔍 DEBUG: runTests() completed successfully");
  } catch (error) {
    console.error("🔍 DEBUG: Error caught in main function");
    console.error("💥 Main function error:", error);
    console.error("Stack:", (error as Error).stack);
  }
  
  console.log("🔍 DEBUG: main function completed");
}

// Only run if this file is executed directly
console.log("🔍 DEBUG: About to check if file is executed directly");
console.log("🔍 DEBUG: import.meta.url:", import.meta.url);
console.log("🔍 DEBUG: process.argv[1]:", process.argv[1]);

// Fix for Windows path comparison
// import { pathToFileURL } from 'url';
const currentFileUrl = import.meta.url;
const mainFileUrl = pathToFileURL(process.argv[1]).href;

console.log("🔍 DEBUG: currentFileUrl:", currentFileUrl);
console.log("🔍 DEBUG: mainFileUrl:", mainFileUrl);
console.log("🔍 DEBUG: URLs match:", currentFileUrl === mainFileUrl);

if (currentFileUrl === mainFileUrl) {
  console.log("🔍 DEBUG: File is being executed directly, calling main()");
  main().catch((error) => {
    console.error("🔍 DEBUG: Error caught in top-level catch");
    console.error("💥 Fatal error:", error);
    console.error("Stack:", error.stack);
    process.exit(1);
  });
} else {
  console.log("🔍 DEBUG: File is being imported, not executed directly");
}

console.log("🔍 DEBUG: Script reached end of file");