import { LoadStrategy } from '@mikro-orm/core';
import { MikroOrmModuleOptions } from '@mikro-orm/nestjs';
import { config } from 'dotenv';
config();

const dbConfig: MikroOrmModuleOptions = {
  type: 'mysql',
  host: process.env.DB_HOST,
  port: Number(process.env.DB_PORT),
  user: process.env.DB_USER,
  dbName: process.env.DB_NAME,
  debug: true,
  entitiesTs: ['./src/**/*.entity.ts'],
  entities: ['./dist/**/*.entity.js'],
  loadStrategy: LoadStrategy.JOINED,
  migrations: {
    pathTs: './src/mikro/migrations',
    path: './dist/mikro/migrations',
  },
  seeder: {
    pathTs: './src/mikro/seeders',
    path: './dist/mikro/seeders',
  },
};

export default dbConfig;
