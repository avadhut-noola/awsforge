// src/utils/tokenManager.ts

import { InitiateAuthCommandOutput } from "@aws-sdk/client-cognito-identity-provider";
import { AuthTokens } from "../types";

export function extractTokens(response: InitiateAuthCommandOutput): AuthTokens {
  const auth = response.AuthenticationResult;

  if (!auth) {
    throw new Error("Authentication failed: No AuthenticationResult present.");
  }

  return {
    accessToken: auth.AccessToken!,
    idToken: auth.IdToken!,
    refreshToken: auth.RefreshToken!,
  };
}
