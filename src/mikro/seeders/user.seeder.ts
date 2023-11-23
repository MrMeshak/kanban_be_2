import { EntityManager } from '@mikro-orm/mysql';
import { Seeder } from '@mikro-orm/seeder';
import * as bcrypt from 'bcrypt';
import { UserFactory } from './factories/user.factory';

export class UserSeeder extends Seeder {
  async run(em: EntityManager) {
    const hashPassword = await bcrypt.hash('password', 10);
    const userFactory = new UserFactory(em);
    userFactory.makeOne({
      email: 'user@test.com',
      password: hashPassword,
    });
    userFactory.make(10, {
      password: hashPassword,
    });
  }
}
