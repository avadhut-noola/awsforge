// test/cognito.test.ts
import { CognitoService } from '../src/services/cognito';
import { devConfig } from './dev-config';

// Test with development config
const cognitoService = new CognitoService(devConfig);

async function testLogin() {
  try {
    const res = await cognitoService.loginUser({
      username: "avadhutn@ssktech.co.in",
      password: "Welcome@123",
    });
    
    console.log("Login successful:", res);
  } catch (err: any) {
    console.error("Login failed:", err.message);
  }
}

testLogin();