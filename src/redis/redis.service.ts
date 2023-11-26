import { Inject, Injectable } from '@nestjs/common';
import Redis from 'ioredis';

export enum RedisPrefix {
  RefreshToken = 'RefreshToken',
}

@Injectable()
export class RedisService {
  constructor(@Inject('RedisClient') private readonly redisClient: Redis) {}

  onModuleDestroy() {
    this.redisClient.disconnect();
  }

  async get(prefix: RedisPrefix, key: string): Promise<string | null> {
    return await this.redisClient.get(`${prefix}:${key}`);
  }

  async delete(prefix: RedisPrefix, key: string) {
    await this.redisClient.del(`${prefix}:${key}`);
  }

  async set(prefix: RedisPrefix, key: string, value: string) {
    await this.redisClient.set(`${prefix}:${key}`, value);
  }

  async setWithExpiry(
    prefix: RedisPrefix,
    key: string,
    value: string,
    expiry: number,
  ) {
    await this.redisClient.set(`${prefix}:${key}`, value, 'EX', expiry);
  }
}
