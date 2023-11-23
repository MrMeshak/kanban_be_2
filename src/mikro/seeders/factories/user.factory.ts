import { Factory, Faker } from '@mikro-orm/seeder';
import { User, UserStatus } from '../../../app/user/enitity/user.entity';
import { randomUUID } from 'crypto';

export class UserFactory extends Factory<User> {
  model = User;

  protected definition(faker: Faker): Partial<User> {
    return {
      id: randomUUID(),
      email: faker.internet.email(),
      password: 'password',
      firstName: faker.name.firstName(),
      lastName: faker.name.lastName(),
      userStatus: UserStatus.ACTIVE,
    };
  }
}
