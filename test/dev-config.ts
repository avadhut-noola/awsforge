// test/dev-config.ts - Only for development/testing
// import dotenv from 'dotenv';

// Load environment variables for development/testing
// dotenv.config();

export const devConfig = {
  clientId: process.env.COGNITO_CLIENT_ID || '',
  clientSecret: process.env.COGNITO_CLIENT_SECRET || '',
  userPoolId: process.env.COGNITO_USER_POOL_ID || '',
  region: process.env.AWS_REGION || 'us-east-1',
};