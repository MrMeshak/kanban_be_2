import { InjectRepository } from '@mikro-orm/nestjs';
import { Injectable } from '@nestjs/common';
import { User } from './enitity/user.entity';
import { EntityRepository } from '@mikro-orm/mysql';

@Injectable()
export class UserService {
  constructor(
    @InjectRepository(User)
    private readonly userRepository: EntityRepository<User>,
  ) {}

  async findUserById(userId: string): Promise<User | null> {
    return await this.userRepository.findOne({ id: userId });
  }
}
