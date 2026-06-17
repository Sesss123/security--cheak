import {
  Injectable,
  CanActivate,
  ExecutionContext,
  UnauthorizedException,
} from '@nestjs/common';
import * as jwt from 'jsonwebtoken';

/**
 * [FIX #26] AuthGuard now performs real JWT verification.
 *
 * Previous code auto-logged in as the first DB user without any token check —
 * a critical security bypass that let unauthenticated callers access all protected
 * endpoints.
 *
 * New behaviour:
 *   1. Extract Bearer token from the Authorization header ONLY.
 *   2. Verify the token signature using JWT_SECRET.
 *   3. Attach the decoded payload to request.user on success.
 *   4. Throw 401 Unauthorized on any failure.
 *
 * [FIX #29] Token is NOT accepted via URL query string to prevent leakage in
 * access logs (e.g. ?token=...). Use the Authorization header exclusively.
 */
@Injectable()
export class AuthGuard implements CanActivate {
  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest();

    // Extract token from "Authorization: Bearer <token>" header only
    const authHeader: string | undefined = request.headers['authorization'];
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      throw new UnauthorizedException('Missing or malformed Authorization header');
    }

    const token = authHeader.slice(7); // Remove "Bearer " prefix

    try {
      const secret = process.env.JWT_SECRET;
      if (!secret) {
        throw new Error('JWT_SECRET environment variable is not set');
      }

      // Verify signature and expiry; throws if invalid
      const payload = jwt.verify(token, secret) as {
        userId: string;
        email: string;
        role: string;
      };

      // Attach decoded payload so controllers can access req.user
      request.user = {
        userId: payload.userId,
        email: payload.email,
        role: payload.role,
      };

      return true;
    } catch (err: any) {
      throw new UnauthorizedException(`Invalid or expired token: ${err.message}`);
    }
  }
}
