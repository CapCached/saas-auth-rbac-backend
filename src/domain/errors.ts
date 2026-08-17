export type ErrorCode =
  | "AUTHENTICATION_REQUIRED"
  | "CONFLICT"
  | "FORBIDDEN"
  | "INTERNAL_ERROR"
  | "INVALID_CREDENTIALS"
  | "INVALID_OR_EXPIRED_TOKEN"
  | "NOT_FOUND"
  | "RATE_LIMITED"
  | "REFRESH_TOKEN_REUSE"
  | "SERVICE_UNAVAILABLE"
  | "VALIDATION_ERROR";

export class AppError extends Error {
  public constructor(
    public readonly statusCode: number,
    public readonly code: ErrorCode,
    message: string,
    public readonly details?: Readonly<Record<string, unknown>>,
  ) {
    super(message);
    this.name = "AppError";
  }
}

export const errors = {
  authenticationRequired: () =>
    new AppError(401, "AUTHENTICATION_REQUIRED", "Authentication is required"),
  conflict: (message = "The request conflicts with current state") =>
    new AppError(409, "CONFLICT", message),
  forbidden: () => new AppError(403, "FORBIDDEN", "Permission denied"),
  invalidCredentials: () =>
    new AppError(401, "INVALID_CREDENTIALS", "Email or password is incorrect"),
  invalidToken: () =>
    new AppError(401, "INVALID_OR_EXPIRED_TOKEN", "Token is invalid or expired"),
  notFound: () => new AppError(404, "NOT_FOUND", "Resource not found"),
  refreshTokenReuse: () =>
    new AppError(401, "REFRESH_TOKEN_REUSE", "Refresh token reuse detected; session revoked"),
  serviceUnavailable: () =>
    new AppError(503, "SERVICE_UNAVAILABLE", "Service temporarily unavailable"),
  validation: (details?: Readonly<Record<string, unknown>>) =>
    new AppError(400, "VALIDATION_ERROR", "Request validation failed", details),
} as const;
