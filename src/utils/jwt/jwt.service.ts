import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import jwt, { ITokenPayload } from 'jsonwebtoken';

declare module 'jsonwebtoken' {
  export interface ITokenPayload extends jwt.JwtPayload {
    sub: string;
    iat: number;
    exp: number;
  }
}

export enum JwtExpiry {
  AUTH_TOKEN_EXPIRY = 60 * 15, //15 mins
  REFRESH_TOKEN_EXPIRY = 60 * 1440, // 24 hours -> 1440 mins
}

@Injectable()
export class JwtService {
  constructor(private readonly configService: ConfigService) {}

  createAuthToken(id: string) {
    return jwt.sign(
      { sub: id },
      this.configService.get<string>('AUTH_TOKEN_SECRET')!,
      {
        expiresIn: JwtExpiry.AUTH_TOKEN_EXPIRY,
      },
    );
  }

  createRefreshToken(id: string) {
    return jwt.sign(
      { sub: id },
      this.configService.get<string>('REFRESH_TOKEN_SECRET')!,
      {
        expiresIn: JwtExpiry.REFRESH_TOKEN_EXPIRY,
      },
    );
  }

  verifyAuthToken(token: string, options?: jwt.VerifyOptions): ITokenPayload {
    return jwt.verify(
      token,
      this.configService.get<string>('AUTH_TOKEN_SECRET')!,
      options,
    ) as ITokenPayload;
  }

  verifyRefreshToken(
    token: string,
    options?: jwt.VerifyOptions,
  ): ITokenPayload {
    return jwt.verify(
      token,
      this.configService.get<string>('REFRESH_TOKEN_SECRET')!,
      options,
    ) as ITokenPayload;
  }
}
