import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import {
  EXP_TIME_ACCESS_TOKEN,
  EXP_TIME_REFRESH_TOKEN,
  SECRET_ACCESS_TOKEN,
  SECRET_REFRESH_TOKEN,
} from 'config';
import { PrismaService } from 'src/common/services/prisma.service';

import * as bcrypt from 'bcrypt';
import { AuthDTO } from './dto/auth.dto';

@Injectable()
export class AuthService {
  constructor(
    private jwtService: JwtService,
    private prisma: PrismaService,
  ) {}

  async signUp(
    data: any,
  ): Promise<{ access_token: string; refresh_token: string; user: any }> {
    const ifUserExist = await this.prisma.user.findFirst({
      where: {
        email: data.email,
      },
    });

    if (ifUserExist) {
      throw new HttpException('User already exists', HttpStatus.CONFLICT);
    }

    data.password = bcrypt.hashSync(data.password, 10);

    const newUser = await this.prisma.user.create({
      data,
    });

    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { password, ...userWithoutPassword } = newUser;

    return {
      access_token: await this.jwtService.signAsync(userWithoutPassword, {
        secret: SECRET_ACCESS_TOKEN,
        expiresIn: EXP_TIME_ACCESS_TOKEN,
      }),
      refresh_token: await this.jwtService.signAsync(
        { id: userWithoutPassword.idUser },
        {
          secret: SECRET_REFRESH_TOKEN,
          expiresIn: EXP_TIME_REFRESH_TOKEN,
        },
      ),
      user: userWithoutPassword,
    };
  }

  async signIn(
    accessData: AuthDTO,
  ): Promise<{ access_token: string; refresh_token: string; user: any }> {
    const user = await this.prisma.user
      .findFirstOrThrow({
        where: {
          email: accessData.email,
        },
      })
      .catch(() => {
        throw new HttpException('Invalid credentials', HttpStatus.UNAUTHORIZED);
      });

    const compare = await bcrypt.compare(accessData.password, user.password);

    if (!compare) {
      throw new HttpException('Invalid credentials', HttpStatus.UNAUTHORIZED);
    }

    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { password, ...userWithoutPassword } = user;
    console.log(userWithoutPassword);

    return {
      access_token: await this.jwtService.signAsync(userWithoutPassword, {
        secret: SECRET_ACCESS_TOKEN,
        expiresIn: EXP_TIME_ACCESS_TOKEN,
      }),
      refresh_token: await this.jwtService.signAsync(
        { id: userWithoutPassword.idUser },
        {
          secret: SECRET_REFRESH_TOKEN,
          expiresIn: EXP_TIME_REFRESH_TOKEN,
        },
      ),
      user: userWithoutPassword,
    };
  }

  async refreshToken(refreshToken: string) {
    const payload = await this.jwtService.verifyAsync(refreshToken, {
      secret: SECRET_REFRESH_TOKEN,
    });

    const user = await this.prisma.user.findFirstOrThrow({
      where: {
        idUser: payload.id,
      },
    });

    if (user === null) {
      throw new HttpException('User not found', HttpStatus.NOT_FOUND);
    }

    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { password, ...userWithoutPassword } = user;

    return {
      access_token: await this.jwtService.signAsync(userWithoutPassword, {
        secret: SECRET_ACCESS_TOKEN,
        expiresIn: EXP_TIME_ACCESS_TOKEN,
      }),
    };
  }
}
