// src/services/cognito.ts
import crypto from 'crypto';
import { PackageConfig, CognitoConfig } from '../config/packageConfig.js';

import {
  CognitoIdentityProviderClient,
  SignUpCommand,
  ConfirmSignUpCommand,
  InitiateAuthCommand,
  ForgotPasswordCommand,
  AuthFlowType,
} from "@aws-sdk/client-cognito-identity-provider";

import {
  UserRegistrationData,
  UserLoginData,
  ForgotPasswordData,
  ConfirmRegistrationData,
} from "../types/index.js";

export class CognitoService {
  private config: PackageConfig;
  private client: CognitoIdentityProviderClient;

  constructor(userConfig: Partial<CognitoConfig> = {}) {
    this.config = new PackageConfig({
      ...userConfig,
      validateCustomAttributes: true,
    });

    // Initialize AWS client with package config
    this.client = new CognitoIdentityProviderClient({
      region: this.config.cognito.region,
      credentials: {
        accessKeyId: process.env.AWS_ACCESS_KEY!,
        secretAccessKey: process.env.AWS_SECRET_KEY!,
      },
    });
  }

  private generateSecretHash(username: string): string | null {
    if (!this.config.cognito.clientSecret) {
      return null; // No secret hash if no client secret
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

  private buildUserAttributes(registrationData: UserRegistrationData): any[] {
    const attributes = [];

    // Standard attributes
    if (registrationData.email) {
      attributes.push({ Name: 'email', Value: registrationData.email });
    }
    if (registrationData.username) {
      attributes.push({ Name: 'preferred_username', Value: registrationData.username });
    }
    if (registrationData.firstName) {
      attributes.push({ Name: 'given_name', Value: registrationData.firstName });
    }
    if (registrationData.lastName) {
      attributes.push({ Name: 'family_name', Value: registrationData.lastName });
    }
    if (registrationData.phoneNumber) {
      attributes.push({ Name: 'phone_number', Value: registrationData.phoneNumber });
    }

    // Custom attributes (validated)
    if (registrationData.customAttributes) {
      const validCustomAttributes = this.validateCustomAttributes(registrationData.customAttributes);
      
      attributes.push(
        ...Object.entries(validCustomAttributes).map(([key, value]) => ({
          Name: `custom:${key}`,
          Value: value,
        }))
      );
    }

    return attributes;
  }

  // Register a new user (UNCONFIRMED)
  async registerUser(registrationData: UserRegistrationData) {
    try {
      const userAttributes = this.buildUserAttributes(registrationData);
      
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

  // Confirm user registration with email OTP
  async confirmUserRegistration({
    username,
    confirmationCode,
  }: ConfirmRegistrationData) {
    const secretHash = this.generateSecretHash(username);
    
    const command = new ConfirmSignUpCommand({
      ClientId: this.config.cognito.clientId,
      Username: username,
      ConfirmationCode: confirmationCode,
      ...(secretHash && { SecretHash: secretHash }),
    });

    return this.client.send(command);
  }

  // Login user after confirmation
  async loginUser({ username, password }: UserLoginData) {
    const authParameters: any = {
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

    return this.client.send(command);
  }

  // Forgot Password Initiation
  async initiateForgotPassword({ username }: ForgotPasswordData) {
    const secretHash = this.generateSecretHash(username);
    
    const command = new ForgotPasswordCommand({
      ClientId: this.config.cognito.clientId,
      Username: username,
      ...(secretHash && { SecretHash: secretHash }),
    });

    return this.client.send(command);
  }
}

// Export configuration presets
export const CognitoConfigs = {
  // Configuration without custom attributes
  minimal: (baseConfig: Omit<CognitoConfig, 'allowedCustomAttributes' | 'validateCustomAttributes'>) => ({
    ...baseConfig,
    allowedCustomAttributes: [],
    validateCustomAttributes: true,
  }),

  // Configuration with common custom attributes
  withCustomAttributes: (
    baseConfig: Omit<CognitoConfig, 'allowedCustomAttributes' | 'validateCustomAttributes'>,
    customAttributes: string[]
  ) => ({
    ...baseConfig,
    allowedCustomAttributes: customAttributes,
    validateCustomAttributes: true,
  }),

  // Configuration that allows any custom attributes (risky)
  permissive: (baseConfig: Omit<CognitoConfig, 'allowedCustomAttributes' | 'validateCustomAttributes'>) => ({
    ...baseConfig,
    validateCustomAttributes: false,
  }),
};