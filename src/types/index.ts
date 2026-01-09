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
  email: string;
  password: string;
  username?: string;
  firstName?: string;
  lastName?: string;
  phoneNumber?: string;
  customAttributes?: Record<string, string>;
}

export interface UserLoginData {
  username: string;
  password: string;
}

export interface ForgotPasswordData {
  username: string;
}

export interface ConfirmRegistrationData {
  username: string;
  confirmationCode: string;
}

// NEW: Additional interfaces for enhanced functionality
export interface ConfirmForgotPasswordData {
  username: string;
  confirmationCode: string;
  newPassword: string;
}

export interface ChangePasswordData {
  accessToken: string;
  previousPassword: string;
  proposedPassword: string;
}

export interface DecodedToken {
  sub: string;
  iss: string;
  aud: string;
  exp: number;
  iat: number;
  token_use: 'access' | 'id';
  username?: string;
  email?: string;
  email_verified?: boolean;
  phone_number?: string;
  phone_number_verified?: boolean;
  given_name?: string;
  family_name?: string;
  preferred_username?: string;
  [key: string]: any; // For custom attributes
}

export interface TokenVerificationResult {
  isValid: boolean;
  decoded?: DecodedToken;
  error?: string;
}

export interface UserProfile {
  username: string;
  attributes: Record<string, string>;
}

// NEW: Authentication response types
export interface AuthTokens {
  accessToken: string;
  idToken: string;
  refreshToken: string;
  expiresIn: number;
}

export interface LoginResponse {
  tokens: AuthTokens;
  user: UserProfile;
}

// NEW: Enhanced configuration options
export interface TokenConfig {
  autoRefresh?: boolean;
  refreshThreshold?: number; // Minutes before expiry to auto-refresh
  onTokenRefresh?: (tokens: AuthTokens) => void;
  onTokenExpired?: () => void;
}

// Error types for better error handling
export interface CognitoError {
  code: string;
  message: string;
  statusCode?: number;
}

// Session management
export interface UserSession {
  tokens: AuthTokens;
  user: UserProfile;
  expiresAt: Date;
  isValid: boolean;
}

// Admin user creation
export interface AdminCreateUserData {
  fullName?: string;
  firstName?: string;
  lastName?: string;
  username: string;
  email: string;
  /** An optional temporary password for the user.
   * If not provided, the user will be in a `FORCE_CHANGE_PASSWORD` 
   * state upon first login. */
  temporaryPassword?: string;
  customAttributes?: Record<string, string>;
}
//Reset Password (For end user after admin user creation)
export interface RespondToNewPasswordChallengeData {
  username: string;
  newPassword: string;
  session: string;
}

// Admin Disable User
export interface AdminDisableUserData {
  username: string;
}

// Admin Enable User
export interface AdminEnableUserData {
  username: string;
}

// Admin Update User Attributes
export interface AdminUpdateUserAttributesData {
  username: string;
  userAttributes: Array<{
    Name: string;
    Value: string;
  }>;
  clientMetadata?: Record<string, string>;
}