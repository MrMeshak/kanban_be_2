import { FactoryProvider } from '@nestjs/common';
import { Redis } from 'ioredis';
import { ConfigService } from '@nestjs/config';

export const redisClientFactory: FactoryProvider<Redis> = {
  provide: 'RedisClient',
  inject: [ConfigService],

  useFactory: async (configService: ConfigService) => {
    const redisInstance = new Redis({
      host: configService.get<string>('REDIS_HOST'),
      port: Number(configService.get<string>('REDIS_PORT')),
    });

    redisInstance.on('error', (error) => {
      throw new Error(`Redis connection failed: ${error}`);
    });

    return redisInstance;
  },
};
