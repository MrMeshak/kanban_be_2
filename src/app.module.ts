import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { UserModule } from './app/user/user.module';
import { MikroOrmModule } from '@mikro-orm/nestjs';
import { RedisModule } from './redis/redis.module';

@Module({
  imports: [
    ConfigModule.forRoot(),
    MikroOrmModule.forRoot(),
    UserModule,
    RedisModule,
  ],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
