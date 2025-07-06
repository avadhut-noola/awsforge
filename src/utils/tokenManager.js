"use strict";
// src/utils/tokenManager.ts
Object.defineProperty(exports, "__esModule", { value: true });
exports.extractTokens = extractTokens;
function extractTokens(response) {
    var auth = response.AuthenticationResult;
    if (!auth) {
        throw new Error("Authentication failed: No AuthenticationResult present.");
    }
    return {
        accessToken: auth.AccessToken,
        idToken: auth.IdToken,
        refreshToken: auth.RefreshToken,
    };
}
