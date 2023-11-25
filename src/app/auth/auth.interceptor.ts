import {
  CallHandler,
  ExecutionContext,
  Injectable,
  Logger,
  NestInterceptor,
} from '@nestjs/common';
import { Observable, map, tap } from 'rxjs';
import * as cookie from 'cookie';
import { Request, Response } from 'express';
import { JwtExpiry, JwtService } from '../../utils/jwt/jwt.service';
import { ITokenPayload } from 'jsonwebtoken';
import { RedisPrefix, RedisService } from '../../redis/redis.service';
import { UserService } from '../user/user.service';
import { UserStatus } from '../user/enitity/user.entity';

export interface AuthContext {
  userId?: string;
  message: string;
}

export interface RequestWithAuthContext extends Request {
  authContext: AuthContext;
}

@Injectable()
export class AuthInterceptor implements NestInterceptor {
  private readonly logger = new Logger(AuthInterceptor.name);

  constructor(
    private readonly jwtService: JwtService,
    private readonly redisService: RedisService,
    private readonly userService: UserService,
  ) {}

  async intercept(
    context: ExecutionContext,
    next: CallHandler<any>,
  ): Promise<Observable<any>> {
    const req: RequestWithAuthContext = context.switchToHttp().getRequest();
    req.authContext = { userId: undefined, message: '' };

    const cookies = cookie.parse(req.headers.cookie ?? '');
    const authToken: string = cookies['authToken'];
    const refreshToken: string = cookies['refreshToken'];

    if (!authToken || !refreshToken) {
      req.authContext = {
        userId: undefined,
        message: 'missing authToken or refreshToken',
      };
      return next.handle();
    }

    let decodedAuthToken: ITokenPayload;
    try {
      decodedAuthToken = this.jwtService.verifyAuthToken(authToken, {
        ignoreExpiration: true,
      });
    } catch (err) {
      console.log(err);
      req.authContext = {
        userId: undefined,
        message: 'invalid authToken',
      };
      return next.handle();
    }

    const userId = decodedAuthToken.sub;
    if (decodedAuthToken.exp * 1000 > Date.now()) {
      req.authContext = {
        userId: userId,
        message: 'authenticated',
      };
      return next.handle();
    }

    let decodedRefreshToken: ITokenPayload;
    try {
      decodedRefreshToken = this.jwtService.verifyRefreshToken(refreshToken);
    } catch (err) {
      req.authContext = {
        userId: undefined,
        message: 'invalid refreshToken',
      };
      return next.handle();
    }

    if (decodedRefreshToken.sub !== authToken) {
      req.authContext = {
        userId: undefined,
        message: 'AuthToken and RefreshToken not paired',
      };
      return next.handle();
    }

    const storedRefreshToken = await this.redisService.get(
      RedisPrefix.RefreshToken,
      userId,
    );

    console.log(storedRefreshToken);
    console.log(refreshToken);
    if (refreshToken !== storedRefreshToken) {
      await this.redisService.delete(RedisPrefix.RefreshToken, userId);
      req.authContext = {
        userId: undefined,
        message: 'refresh token has already been used',
      };
      console.log(req.authContext);
      return next.handle();
    }

    const user = await this.userService.findUserById(userId);

    if (!user) {
      req.authContext = {
        userId: undefined,
        message: 'user could not be found',
      };
      return next.handle();
    }

    if (user.userStatus === UserStatus.SUSPENDED) {
      req.authContext = {
        userId: undefined,
        message: 'user suspended',
      };
      return next.handle();
    }

    req.authContext = {
      userId: userId,
      message: 'authenticated',
    };

    return next.handle().pipe(
      tap(async () => {
        const res: Response = context.switchToHttp().getResponse();
        const authToken = this.jwtService.createAuthToken(userId);
        const refreshToken = this.jwtService.createRefreshToken(authToken);
        await this.redisService.set(
          RedisPrefix.RefreshToken,
          userId,
          refreshToken,
        );
        res.setHeader('Set-Cookie', [
          cookie.serialize('authToken', authToken, {
            httpOnly: true,
            sameSite: 'strict',
            secure: true,
            maxAge: JwtExpiry.AUTH_TOKEN_EXPIRY,
          }),
          cookie.serialize('refreshToken', refreshToken, {
            httpOnly: true,
            sameSite: 'strict',
            secure: true,
            maxAge: JwtExpiry.REFRESH_TOKEN_EXPIRY,
          }),
        ]);
      }),
    );
  }
}
