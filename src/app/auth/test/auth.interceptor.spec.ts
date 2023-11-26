import { ExecutionContext } from '@nestjs/common';
import { CallHandler } from '@nestjs/common/interfaces';
import { Response } from 'express';
import { of } from 'rxjs';
import { AuthInterceptor, RequestWithAuthContext } from '../auth.interceptor';
import { JwtExpiry, JwtService } from '../../../utils/jwt/jwt.service';
import { RedisPrefix, RedisService } from '../../../redis/redis.service';
import { UserService } from '../../../app/user/user.service';
import { Test } from '@nestjs/testing';
import { DeepMockProxy, mockDeep } from 'jest-mock-extended';
import { VerifyErrors } from 'jsonwebtoken';
import { User, UserStatus } from '../../user/enitity/user.entity';

describe('auth - AuthInterceptor', () => {
  const req = mockDeep<RequestWithAuthContext>();
  const res = mockDeep<Response>();

  const mockUserService = mockDeep<UserService>();
  const mockRedisService = mockDeep<RedisService>();
  const mockJwtService = mockDeep<JwtService>();

  const mockExecutionContext: ExecutionContext = {
    switchToHttp: () => ({
      getRequest: () => req,
      getResponse: () => res,
    }),
  } as ExecutionContext;

  const mockNext: CallHandler = {
    handle: () => of(),
  } as CallHandler;

  let authInterceptor: AuthInterceptor;

  beforeEach(async () => {
    jest.clearAllMocks();

    const moduleRef = await Test.createTestingModule({
      providers: [JwtService, RedisService, UserService],
    })
      .overrideProvider(UserService)
      .useValue(mockUserService)
      .overrideProvider(RedisService)
      .useValue(mockRedisService)
      .overrideProvider(JwtService)
      .useValue(mockJwtService)
      .compile();

    const userService = moduleRef.get<DeepMockProxy<UserService>>(UserService);
    const redisService =
      moduleRef.get<DeepMockProxy<RedisService>>(RedisService);
    const jwtService = moduleRef.get<DeepMockProxy<JwtService>>(JwtService);

    authInterceptor = new AuthInterceptor(
      jwtService,
      redisService,
      userService,
    );
  });

  describe('when the req does not contain an authToken or refreshToken', () => {
    it('should set authContext - {userId: undefined, message: message}', async () => {
      req.headers.cookie = '';

      await authInterceptor.intercept(mockExecutionContext, mockNext);

      expect(req.authContext).toEqual({
        userId: undefined,
        message: 'missing authToken or refreshToken',
      });
    });
  });

  describe('when the authToken is invalid', () => {
    it('should set authContext - {userId: undefined, message: message}', async () => {
      req.headers.cookie = 'authToken=authToken;refreshToken=refreshToken;';

      mockJwtService.verifyAuthToken.mockImplementation(() => {
        throw new Error('invalid token');
      });

      await authInterceptor.intercept(mockExecutionContext, mockNext);

      expect(req.authContext).toEqual({
        userId: undefined,
        message: 'invalid authToken',
      });
    });
  });

  describe('when the authToken is valid and not expired', () => {
    it('should set authContext - {userId: userId, message: message}', async () => {
      req.headers.cookie = 'authToken=authToken;refreshToken=refreshToken;';
      mockJwtService.verifyAuthToken.mockReturnValue({
        sub: 'userId',
        exp: Date.now() / 1000 + JwtExpiry.AUTH_TOKEN_EXPIRY,
        iat: Date.now() / 1000,
      });

      await authInterceptor.intercept(mockExecutionContext, mockNext);

      expect(req.authContext).toEqual({
        userId: 'userId',
        message: 'authenticated',
      });
    });
  });

  describe('when the authToken is valid but has expired and the refreshToken is invalid or expired', () => {
    it('should set authContext = {userId: undefined, message: message}', async () => {
      req.headers.cookie = 'authToken=authToken;refreshToken=refreshToken;';
      mockJwtService.verifyAuthToken.mockReturnValue({
        sub: 'userId',
        exp: Date.now() / 1000 - JwtExpiry.AUTH_TOKEN_EXPIRY,
        iat: Date.now() / 1000 - JwtExpiry.REFRESH_TOKEN_EXPIRY,
      });
      mockJwtService.verifyRefreshToken.mockImplementation(() => {
        throw new Error('invalid token');
      });

      await authInterceptor.intercept(mockExecutionContext, mockNext);

      expect(req.authContext).toEqual({
        userId: undefined,
        message: 'invalid refreshToken',
      });
    });
  });

  describe('when the authToken is valid but has expired, the refreshToken is valid but does not make a matched paired with the authToken', () => {
    it('should set authContext = {userId: undefined, message: message}', async () => {
      req.headers.cookie = 'authToken=authToken;refreshToken=refreshToken;';
      mockJwtService.verifyAuthToken.mockReturnValue({
        sub: 'userId',
        exp: Date.now() / 1000 - JwtExpiry.AUTH_TOKEN_EXPIRY,
        iat: Date.now() / 1000 - JwtExpiry.REFRESH_TOKEN_EXPIRY,
      });
      mockJwtService.verifyRefreshToken.mockReturnValue({
        sub: 'differentTokenString',
        exp: Date.now() / 1000 + JwtExpiry.REFRESH_TOKEN_EXPIRY,
        iat: Date.now() / 1000,
      });

      await authInterceptor.intercept(mockExecutionContext, mockNext);

      expect(req.authContext).toEqual({
        userId: undefined,
        message: 'AuthToken and RefreshToken not paired',
      });
    });
  });

  describe('when the authToken is valid but has expired, the refreshToken is valid but does not match storedRefreshToken (i.e the refreshToken has already been used)', () => {
    it('Should delete storedRefreshToken and set authContext = {userId: undefined, message: message}', async () => {
      req.headers.cookie = 'authToken=authToken;refreshToken=refreshToken;';
      mockJwtService.verifyAuthToken.mockReturnValue({
        sub: 'userId',
        exp: Date.now() / 1000 - JwtExpiry.AUTH_TOKEN_EXPIRY,
        iat: Date.now() / 1000 - JwtExpiry.REFRESH_TOKEN_EXPIRY,
      });
      mockJwtService.verifyRefreshToken.mockReturnValue({
        sub: 'authToken',
        exp: Date.now() / 1000 + JwtExpiry.REFRESH_TOKEN_EXPIRY,
        iat: Date.now() / 1000,
      });

      mockRedisService.get.mockResolvedValue('storedRefreshToken');

      await authInterceptor.intercept(mockExecutionContext, mockNext);

      expect(mockRedisService.delete).toHaveBeenCalledWith(
        RedisPrefix.RefreshToken,
        'userId',
      );
      expect(req.authContext).toEqual({
        userId: undefined,
        message: 'refresh token has already been used',
      });
    });
  });

  describe('when the authToken is valid but has expired, the refreshToken is valid and matches storedRefreshToken but the user does not exist in db', () => {
    it('should set authContext = {userId: undefined, message: message}', async () => {
      req.headers.cookie = 'authToken=authToken;refreshToken=refreshToken;';
      mockJwtService.verifyAuthToken.mockReturnValue({
        sub: 'userId',
        exp: Date.now() / 1000 - JwtExpiry.AUTH_TOKEN_EXPIRY,
        iat: Date.now() / 1000 - JwtExpiry.REFRESH_TOKEN_EXPIRY,
      });
      mockJwtService.verifyRefreshToken.mockReturnValue({
        sub: 'authToken',
        exp: Date.now() / 1000 + JwtExpiry.REFRESH_TOKEN_EXPIRY,
        iat: Date.now() / 1000,
      });

      mockRedisService.get.mockResolvedValue('refreshToken');
      mockUserService.findUserById.mockResolvedValue(null);

      await authInterceptor.intercept(mockExecutionContext, mockNext);

      expect(req.authContext).toEqual({
        userId: undefined,
        message: 'user could not be found',
      });
    });
  });

  describe('when authToken is valid but has expired, the refreshToken is valid and matches storedRefreshToken but the user is suspended', () => {
    it('should set authContext = {userId: undefined, message: message}', async () => {
      req.headers.cookie = 'authToken=authToken;refreshToken=refreshToken;';
      mockJwtService.verifyAuthToken.mockReturnValue({
        sub: 'userId',
        exp: Date.now() / 1000 - JwtExpiry.AUTH_TOKEN_EXPIRY,
        iat: Date.now() / 1000 - JwtExpiry.REFRESH_TOKEN_EXPIRY,
      });
      mockJwtService.verifyRefreshToken.mockReturnValue({
        sub: 'authToken',
        exp: Date.now() / 1000 + JwtExpiry.REFRESH_TOKEN_EXPIRY,
        iat: Date.now() / 1000,
      });

      mockRedisService.get.mockResolvedValue('refreshToken');
      mockUserService.findUserById.mockResolvedValue({
        userStatus: UserStatus.SUSPENDED,
      } as User);

      await authInterceptor.intercept(mockExecutionContext, mockNext);

      expect(req.authContext).toEqual({
        userId: undefined,
        message: 'user suspended',
      });
    });
  });

  describe('when authToken is valid but has expired, the refreshToken is valid and matches storedRefreshToken and the user exists and is not suspended', () => {
    it('should set authContext = {userId: userId, message: message}, create new authToken and refreshToken, store the new refreshToken, attach the new tokens to the response as cookies', async () => {
      req.headers.cookie = 'authToken=authToken;refreshToken=refreshToken;';
      mockJwtService.verifyAuthToken.mockReturnValue({
        sub: 'userId',
        exp: Date.now() / 1000 - JwtExpiry.AUTH_TOKEN_EXPIRY,
        iat: Date.now() / 1000 - JwtExpiry.REFRESH_TOKEN_EXPIRY,
      });
      mockJwtService.verifyRefreshToken.mockReturnValue({
        sub: 'authToken',
        exp: Date.now() / 1000 + JwtExpiry.REFRESH_TOKEN_EXPIRY,
        iat: Date.now() / 1000,
      });

      mockRedisService.get.mockResolvedValue('refreshToken');
      mockUserService.findUserById.mockResolvedValue({
        userStatus: UserStatus.ACTIVE,
      } as User);

      mockJwtService.createAuthToken.mockReturnValue('newAuthToken');
      mockJwtService.createRefreshToken.mockReturnValue('newRefreshToken');

      (
        await authInterceptor.intercept(mockExecutionContext, mockNext)
      ).subscribe({
        next: () => {
          expect(req.headers.cookie).toBe(
            'authToken=newAuthToken;refreshToken=newRefreshToken;',
          );
          expect(mockRedisService.set).toHaveBeenCalledWith(
            RedisPrefix.RefreshToken,
            'userId',
            'newRefreshToken',
          );
        },
      });

      expect(req.authContext).toEqual({
        userId: 'userId',
        message: 'authenticated',
      });
    });
  });
});
