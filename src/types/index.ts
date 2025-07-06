/**
 * Core types and interfaces for AWSForge
 */

export interface AWSForgeConfig {
  region: string;
  userPoolId: string;
  clientId: string;
  clientSecret?: string;
  accessKeyId?: string;
  secretAccessKey?: string;
  sessionToken?: string;
}

export interface UserRegistrationData {
  username: string;
  password: string;
  email: string;
  firstName?: string;
  lastName?: string;
  phoneNumber?: string;
  customAttributes?: Record<string, string>;
}

export interface ConfirmRegistrationData {
  username: string;
  confirmationCode: string;
}

export interface UserLoginData {
  username: string;
  password: string;
}

export interface ForgotPasswordData {
  username: string;
}

export interface ResetPasswordData {
  username: string;
  confirmationCode: string;
  newPassword: string;
}

export interface AuthTokens {
  accessToken: string;
  idToken: string;
  refreshToken: string;
}

export interface AuthResponse {
  success: boolean;
  message: string;
  data?: any;
  tokens?: AuthTokens;
  error?: string;
}

export interface CognitoUserAttributes {
  [key: string]: string;
}

export interface DecodedJWT {
  sub: string;
  email: string;
  email_verified: boolean;
  iss: string;
  aud: string;
  token_use: string;
  exp: number;
  iat: number;
  [key: string]: any;
}

export interface CookieOptions {
  httpOnly?: boolean;
  secure?: boolean;
  sameSite?: 'strict' | 'lax' | 'none';
  maxAge?: number;
  domain?: string;
  path?: string;
}

export interface AWSForgeError extends Error {
  code: string;
  statusCode: number;
  retryable?: boolean;
}