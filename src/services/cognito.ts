// src/services/cognito.ts
import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import jwksClient from 'jwks-rsa';
import { PackageConfig, CognitoConfig } from '../config/packageConfig.js';

import {
  CognitoIdentityProviderClient,
  SignUpCommand,
  ConfirmSignUpCommand,
  InitiateAuthCommand,
  ForgotPasswordCommand,
  ConfirmForgotPasswordCommand,
  GetUserCommand,
  ChangePasswordCommand,
  DeleteUserCommand,
  ResendConfirmationCodeCommand,
  RevokeTokenCommand,
  AdminCreateUserCommand,
  RespondToAuthChallengeCommand,
  ChallengeNameType,
  AuthFlowType,
  AdminDeleteUserCommand,
  AdminDeleteUserCommandOutput,
  AdminDisableUserCommand,
  AdminDisableUserCommandOutput,
  AdminEnableUserCommand,
  AdminEnableUserCommandOutput,
  AdminUpdateUserAttributesCommand,
  AdminUpdateUserAttributesCommandOutput,
} from "@aws-sdk/client-cognito-identity-provider";

import {
  UserRegistrationData,
  UserLoginData,
  ForgotPasswordData,
  ConfirmRegistrationData,
  TokenVerificationResult,
  DecodedToken,
  UserProfile,
  ChangePasswordData,
  ConfirmForgotPasswordData,
  AdminCreateUserData,
  RespondToNewPasswordChallengeData,
  AdminDisableUserData,
  AdminEnableUserData,
  AdminUpdateUserAttributesData,
} from "../types/index.js";

export class CognitoService {
  private config: PackageConfig;
  private client: CognitoIdentityProviderClient;
  private jwksClient: jwksClient.JwksClient;

  constructor(userConfig: Partial<CognitoConfig> = {}) {
    this.config = new PackageConfig({
      ...userConfig,
      validateCustomAttributes: true,
    });

    // Initialize AWS client with package config
    // Using default credential provider chain instead of explicit credentials
    this.client = new CognitoIdentityProviderClient({
      region: this.config.cognito.region,
    });

    // Initialize JWKS client for token verification
    this.jwksClient = jwksClient({
      jwksUri: `https://cognito-idp.${this.config.cognito.region}.amazonaws.com/${this.config.cognito.userPoolId}/.well-known/jwks.json`,
      cache: true,
      cacheMaxAge: 3600000, // 1 hour
      cacheMaxEntries: 5,
    });
  }

  private generateSecretHash(username: string): string | undefined {
    if (!this.config.cognito.clientSecret) {
      return undefined;
    }
    
    const message = username + this.config.cognito.clientId;
    return crypto
      .createHmac('sha256', this.config.cognito.clientSecret)
      .update(message)
      .digest('base64');
  }

  private validateCustomAttributes(customAttributes: Record<string, string>): Record<string, string> {
    if (!this.config.validateCustomAttributes) {
      return customAttributes;
    }

    if (!this.config.allowedCustomAttributes || this.config.allowedCustomAttributes.length === 0) {
      console.warn('No custom attributes are configured. Skipping custom attributes.');
      return {};
    }

    const validAttributes: Record<string, string> = {};
    const invalidAttributes: string[] = [];

    for (const [key, value] of Object.entries(customAttributes)) {
      if (this.config.allowedCustomAttributes.includes(key)) {
        validAttributes[key] = value;
      } else {
        invalidAttributes.push(key);
      }
    }

    if (invalidAttributes.length > 0) {
      console.warn(`Invalid custom attributes ignored: ${invalidAttributes.join(', ')}`);
      console.warn(`Allowed custom attributes: ${this.config.allowedCustomAttributes.join(', ')}`);
    }

    return validAttributes;
  }

  private buildUserAttributes(
    userData: {
      email?: string;
      username?: string;
      firstName?: string;
      lastName?: string;
      phoneNumber?: string;
      customAttributes?: Record<string, string>;
    },
    isAdminCreate = false
  ): any[] {
    const attributes = [];

    if (userData.email) {
      attributes.push({ Name: 'email', Value: userData.email });
      if (isAdminCreate) {
        attributes.push({ Name: 'email_verified', Value: 'true' });
      }
    }
    if (userData.username) {
      attributes.push({ Name: 'preferred_username', Value: userData.username });
    }
    if (userData.firstName) {
      attributes.push({ Name: 'given_name', Value: userData.firstName });
    }
    if (userData.lastName) {
      attributes.push({ Name: 'family_name', Value: userData.lastName });
    }
    if (userData.phoneNumber) {
      attributes.push({ Name: 'phone_number', Value: userData.phoneNumber });
    }

    if (userData.customAttributes) {
      const validCustomAttributes = this.validateCustomAttributes(userData.customAttributes);
      
      attributes.push(
        ...Object.entries(validCustomAttributes).map(([key, value]) => ({
          Name: `custom:${key}`,
          Value: value,
        }))
      );
    }

    return attributes;
  }

  // Token Verification Methods
  async verifyToken(token: string, skipAudienceCheck: boolean = false): Promise<TokenVerificationResult> {
    try {
      const decoded = jwt.decode(token, { complete: true }) as any;
      
      if (!decoded || !decoded.header || !decoded.payload) {
        return {
          isValid: false,
          error: 'Invalid token format',
        };
      }

      // Get the signing key
      const key = await this.jwksClient.getSigningKey(decoded.header.kid);
      const signingKey = key.getPublicKey();

      // Verify token with or without audience check
      const verifyOptions: jwt.VerifyOptions = {
        issuer: `https://cognito-idp.${this.config.cognito.region}.amazonaws.com/${this.config.cognito.userPoolId}`,
      };

      // Only check audience for ID tokens, not access tokens
      if (!skipAudienceCheck) {
        verifyOptions.audience = this.config.cognito.clientId;
      }

      const payload = jwt.verify(token, signingKey, verifyOptions) as DecodedToken;

      // Check if token is expired
      const currentTime = Math.floor(Date.now() / 1000);
      if (payload.exp < currentTime) {
        return {
          isValid: false,
          error: 'Token expired',
          decoded: payload,
        };
      }

      return {
        isValid: true,
        decoded: payload,
      };
    } catch (error) {
      return {
        isValid: false,
        error: error instanceof Error ? error.message : 'Token verification failed',
      };
    }
  }

  async verifyAccessToken(accessToken: string): Promise<TokenVerificationResult> {
    // Skip audience check for access tokens as they use User Pool ID as audience
    const result = await this.verifyToken(accessToken, true);
    
    if (result.isValid && result.decoded?.token_use && result.decoded.token_use !== 'access') {
      return {
        isValid: false,
        error: 'Token is not an access token',
        decoded: result.decoded,
      };
    }
    
    return result;
  }

  async verifyIdToken(idToken: string): Promise<TokenVerificationResult> {
    // Use audience check for ID tokens
    const result = await this.verifyToken(idToken, false);
    
    if (result.isValid && result.decoded?.token_use && result.decoded.token_use !== 'id') {
      return {
        isValid: false,
        error: 'Token is not an ID token',
        decoded: result.decoded,
      };
    }
    
    return result;
  }

  // Get user profile from token
  async getUserFromToken(accessToken: string): Promise<UserProfile> {
    const command = new GetUserCommand({
      AccessToken: accessToken,
    });

    const response = await this.client.send(command);
    
    const userProfile: UserProfile = {
      username: response.Username!,
      attributes: {},
    };

    response.UserAttributes?.forEach(attr => {
      if (attr.Name && attr.Value) {
        userProfile.attributes[attr.Name] = attr.Value;
      }
    });

    return userProfile;
  }

  // Helper method to extract username from JWT token - IMPROVED
  private extractUsernameFromToken(refreshToken: string): string | undefined {
    try {
      const decoded = jwt.decode(refreshToken) as any;
      
      // For Cognito refresh tokens, we need to use the SUB (subject) for SecretHash
      // This is a poorly documented requirement from AWS Cognito
      return decoded?.username || 
             decoded?.email || 
             decoded?.sub || 
             decoded?.preferred_username || 
             undefined;
    } catch (error) {
      console.error('Error extracting username from token:', error);
      return undefined;
    }
  }

  // Helper method to get SUB from access token
  private getSubFromAccessToken(accessToken: string): string | undefined {
    try {
      const decoded = jwt.decode(accessToken) as any;
      return decoded?.sub;
    } catch (error) {
      console.error('Error extracting SUB from access token:', error);
      return undefined;
    }
  }

  // Refresh tokens - FIXED VERSION with SUB handling
  async refreshTokens(refreshToken: string, username?: string, accessToken?: string) {
    const authParameters: any = {
      REFRESH_TOKEN: refreshToken,
    };

    // If client secret is configured, we need SECRET_HASH
    if (this.config.cognito.clientSecret) {
      let usernameForHash = username;
      
      // Try to get SUB from access token first (most reliable for refresh)
      if (!usernameForHash && accessToken) {
        try {
          const userProfile = await this.getUserFromToken(accessToken);
          usernameForHash = userProfile.attributes.sub || userProfile.username;
          console.log('Using SUB from user profile for SECRET_HASH:', usernameForHash);
        } catch (error) {
          console.warn('Could not get user profile from access token:', error);
          // Fall back to token extraction
          usernameForHash = this.getSubFromAccessToken(accessToken);
        }
      }
      
      // If still no username, try to extract from refresh token
      if (!usernameForHash) {
        usernameForHash = this.extractUsernameFromToken(refreshToken);
      }
      
      if (!usernameForHash) {
        throw new Error('Username/SUB is required for refresh token when using client secret. Cannot extract from tokens.');
      }
      
      console.log('Using username/SUB for SECRET_HASH:', usernameForHash);
      const secretHash = this.generateSecretHash(usernameForHash);
      if (secretHash) {
        authParameters.SECRET_HASH = secretHash;
      }
    }

    const command = new InitiateAuthCommand({
      AuthFlow: AuthFlowType.REFRESH_TOKEN_AUTH,
      ClientId: this.config.cognito.clientId,
      AuthParameters: authParameters,
    });

    return this.client.send(command);
  }

  // Refresh tokens with explicit username (for backwards compatibility)
  async refreshTokensWithUsername(refreshToken: string, username: string, accessToken?: string) {
    return this.refreshTokens(refreshToken, username, accessToken);
  }

  // Revoke tokens (logout)
  async revokeToken(token: string) {
    const command = new RevokeTokenCommand({
      ClientId: this.config.cognito.clientId,
      Token: token,
    });

    return this.client.send(command);
  }

  // Change password
  async changePassword({ accessToken, previousPassword, proposedPassword }: ChangePasswordData) {
    const command = new ChangePasswordCommand({
      AccessToken: accessToken,
      PreviousPassword: previousPassword,
      ProposedPassword: proposedPassword,
    });

    return this.client.send(command);
  }

  // Confirm forgot password
  async confirmForgotPassword({ username, confirmationCode, newPassword }: ConfirmForgotPasswordData) {
    const secretHash = this.generateSecretHash(username);
    
    const command = new ConfirmForgotPasswordCommand({
      ClientId: this.config.cognito.clientId,
      Username: username,
      ConfirmationCode: confirmationCode,
      Password: newPassword,
      ...(secretHash && { SecretHash: secretHash }),
    });

    return this.client.send(command);
  }

  // Resend confirmation code
  async resendConfirmationCode(username: string) {
    const secretHash = this.generateSecretHash(username);
    
    const command = new ResendConfirmationCodeCommand({
      ClientId: this.config.cognito.clientId,
      Username: username,
      ...(secretHash && { SecretHash: secretHash }),
    });

    return this.client.send(command);
  }

  // Delete user
  async deleteUser(accessToken: string) {
    const command = new DeleteUserCommand({
      AccessToken: accessToken,
    });

    return this.client.send(command);
  }

  /**
   * Creates a new user in the user pool as an administrator.
   * This action does not require a client secret but does require AWS credentials with admin permissions.
   * It can set a temporary password and bypasses the confirmation loop by marking the email as verified.
   * @param userData - The user data for the new user.
   * @returns The result of the AdminCreateUser command.
   */
  async adminCreateUser(userData: AdminCreateUserData) {
    try {
      // The `buildUserAttributes` method is reused here.
      // The `true` flag marks the user's email as verified.
      const userAttributes = this.buildUserAttributes(userData, true);

      const command = new AdminCreateUserCommand({
        UserPoolId: this.config.cognito.userPoolId,
        Username: userData.email,
        UserAttributes: userAttributes,
        TemporaryPassword: userData.temporaryPassword,
        // Suppress the default welcome email from Cognito.
        // Your application should handle notifying the user with their temporary password.
        MessageAction: 'SUPPRESS',
      });

      const response = await this.client.send(command);
      return response;
    } catch (error) {
      console.error('Admin user creation error:', error);
      throw error;
    }
  }

  async adminDeleteUser({ username }: { username: string }): Promise<AdminDeleteUserCommandOutput> {
    try {
      const command = new AdminDeleteUserCommand({
        UserPoolId: this.config.cognito.userPoolId,
        Username: username,
      });
      return await this.client.send(command);
    } catch (error) {
      console.error(`Admin user deletion error for user ${username}:`, error);
      throw error;
    }
  }

  // Existing methods remain the same
  async registerUser(registrationData: UserRegistrationData) {
    try {
      const userAttributes = this.buildUserAttributes(registrationData, false);
      
      console.log('Registering user with attributes:', userAttributes);

      const secretHash = this.generateSecretHash(registrationData.email);
      
      const command = new SignUpCommand({
        ClientId: this.config.cognito.clientId,
        Username: registrationData.email,
        Password: registrationData.password,
        UserAttributes: userAttributes,
        ...(secretHash && { SecretHash: secretHash }),
      });

      const response = await this.client.send(command);
      return response;
    } catch (error) {
      console.error('Registration error:', error);
      throw error;
    }
  }

  async confirmUserRegistration({ username, confirmationCode }: ConfirmRegistrationData) {
    const secretHash = this.generateSecretHash(username);
    
    const command = new ConfirmSignUpCommand({
      ClientId: this.config.cognito.clientId,
      Username: username,
      ConfirmationCode: confirmationCode,
      ...(secretHash && { SecretHash: secretHash }),
    });

    return this.client.send(command);
  }

  async loginUser({ username, password }: { username: string; password: string }) {
    const authParameters: Record<string, string> = {
      USERNAME: username,
      PASSWORD: password,
    };

    const secretHash = this.generateSecretHash(username);
    if (secretHash) {
      authParameters.SECRET_HASH = secretHash;
    }

    const command = new InitiateAuthCommand({
      AuthFlow: AuthFlowType.USER_PASSWORD_AUTH,
      ClientId: this.config.cognito.clientId,
      AuthParameters: authParameters,
    });

    const response = await this.client.send(command);

    // IMPORTANT: just return whatever Cognito gives back
    // It may contain AuthenticationResult (normal login)
    // OR ChallengeName + Session (e.g., NEW_PASSWORD_REQUIRED)
    return response;
  }

  async respondToNewPasswordChallenge({
    username,
    newPassword,
    session,
  }: RespondToNewPasswordChallengeData) {
    const challengeResponses: any = {
      USERNAME: username,
      NEW_PASSWORD: newPassword,
    };

    const secretHash = this.generateSecretHash(username);
    if (secretHash) {
      challengeResponses.SECRET_HASH = secretHash;
    }

    const command = new RespondToAuthChallengeCommand({
      ClientId: this.config.cognito.clientId,
      ChallengeName: ChallengeNameType.NEW_PASSWORD_REQUIRED,
      Session: session,
      ChallengeResponses: challengeResponses,
    });

    return this.client.send(command);
  }

  async initiateForgotPassword({ username }: ForgotPasswordData) {
    const secretHash = this.generateSecretHash(username);
    
    const command = new ForgotPasswordCommand({
      ClientId: this.config.cognito.clientId,
      Username: username,
      ...(secretHash && { SecretHash: secretHash }),
    });

    return this.client.send(command);
  }

  /**
   * Disables a user in the user pool as an administrator.
   * This action requires AWS credentials with admin permissions.
   * A deactivated user can't sign in, but still appears in the responses to ListUsers API requests.
   * @param userData - The user data containing the username to disable.
   * @returns The result of the AdminDisableUser command.
   */
  async adminDisableUser({ username }: AdminDisableUserData): Promise<AdminDisableUserCommandOutput> {
    const command = new AdminDisableUserCommand({
      UserPoolId: this.config.cognito.userPoolId,
      Username: username,
    });

    try {
      const response = await this.client.send(command);
      return response;
    } catch (error) {
      console.error('Error disabling user:', error);
      throw error;
    }
  }

  /**
   * Enables a user in the user pool as an administrator.
   * This action requires AWS credentials with admin permissions.
   * Activates sign-in for a user profile that previously had sign-in access disabled.
   * @param userData - The user data containing the username to enable.
   * @returns The result of the AdminEnableUser command.
   */
  async adminEnableUser({ username }: AdminEnableUserData): Promise<AdminEnableUserCommandOutput> {
    const command = new AdminEnableUserCommand({
      UserPoolId: this.config.cognito.userPoolId,
      Username: username,
    });

    try {
      const response = await this.client.send(command);
      return response;
    } catch (error) {
      console.error('Error enabling user:', error);
      throw error;
    }
  }

  /**
   * Updates the specified user's attributes as an administrator.
   * This action requires AWS credentials with admin permissions.
   * Can set a user's email address or phone number as verified.
   * To delete an attribute, submit the attribute with a blank value.
   * @param userData - The user data containing username, attributes, and optional client metadata.
   * @returns The result of the AdminUpdateUserAttributes command.
   */
  async adminUpdateUserAttributes({
    username,
    userAttributes,
    clientMetadata,
  }: AdminUpdateUserAttributesData): Promise<AdminUpdateUserAttributesCommandOutput> {
    const command = new AdminUpdateUserAttributesCommand({
      UserPoolId: this.config.cognito.userPoolId,
      Username: username,
      UserAttributes: userAttributes,
      ClientMetadata: clientMetadata,
    });

    try {
      const response = await this.client.send(command);
      return response;
    } catch (error) {
      console.error('Error updating user attributes:', error);
      throw error;
    }
  }
}

// Export configuration presets
export const CognitoConfigs = {
  minimal: (baseConfig: Omit<CognitoConfig, 'allowedCustomAttributes' | 'validateCustomAttributes'>) => ({
    ...baseConfig,
    allowedCustomAttributes: [],
    validateCustomAttributes: true,
  }),

  withCustomAttributes: (
    baseConfig: Omit<CognitoConfig, 'allowedCustomAttributes' | 'validateCustomAttributes'>,
    customAttributes: string[]
  ) => ({
    ...baseConfig,
    allowedCustomAttributes: customAttributes,
    validateCustomAttributes: true,
  }),

  permissive: (baseConfig: Omit<CognitoConfig, 'allowedCustomAttributes' | 'validateCustomAttributes'>) => ({
    ...baseConfig,
    validateCustomAttributes: false,
  }),
};