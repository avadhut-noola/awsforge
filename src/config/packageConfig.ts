// src/config/packageConfig.ts
export interface CognitoConfig {
  clientId: string;
  clientSecret?: string;
  userPoolId: string;
  region: string;
  allowedCustomAttributes?: string[];
  validateCustomAttributes?: boolean;
}

export class PackageConfig {
  public readonly cognito: CognitoConfig;
  public readonly allowedCustomAttributes: string[];
  public readonly validateCustomAttributes: boolean;

  constructor(config: Partial<CognitoConfig> = {}) {
    this.cognito = {
      clientId: config.clientId || process.env.COGNITO_CLIENT_ID || '',
      clientSecret: config.clientSecret || process.env.COGNITO_CLIENT_SECRET,
      userPoolId: config.userPoolId || process.env.COGNITO_USER_POOL_ID || '',
      region: config.region || process.env.AWS_REGION || 'us-east-1',
      allowedCustomAttributes: config.allowedCustomAttributes || [],
      validateCustomAttributes: config.validateCustomAttributes ?? true,
    };

    // Set top-level properties for easier access
    this.allowedCustomAttributes = this.cognito.allowedCustomAttributes || [];
    this.validateCustomAttributes = this.cognito.validateCustomAttributes ?? true;
    
    // Validate required fields
    if (!this.cognito.clientId) {
      throw new Error('Cognito clientId is required');
    }
    if (!this.cognito.userPoolId) {
      throw new Error('Cognito userPoolId is required');
    }
  }
}