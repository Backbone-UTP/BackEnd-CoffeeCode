import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpException,
  HttpStatus,
  Post,
  Req,
  Res,
  UsePipes,
  ValidationPipe,
} from '@nestjs/common';
import { Response, Request } from 'express';
import { AuthService } from './auth.service';
import { Public } from 'src/common/decorators/custom.decoratos';
import { AuthDTO } from './dto/auth.dto';
import { EXP_TIME_ACCESS_TOKEN_MS, EXP_TIME_REFRESH_TOKEN_MS } from 'config';
import { CreateAuthDto } from './dto/create-auth.dto';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Public()
  @HttpCode(HttpStatus.CREATED)
  @Post('signup')
  @UsePipes(new ValidationPipe())
  async signUp(
    @Body() data: CreateAuthDto,
    @Res({ passthrough: true }) response: Response,
  ) {
    const { access_token, refresh_token, user } = await this.authService
      .signUp(data)
      .catch((e) => {
        throw new HttpException(e.message, e.status);
      });

    return response
      .cookie('access_token', access_token, {
        httpOnly: true,
        secure: false,
        expires: new Date(Date.now() + Number(EXP_TIME_ACCESS_TOKEN_MS)),
      })
      .cookie('refresh_token', refresh_token, {
        httpOnly: true,
        secure: false,
        expires: new Date(Date.now() + Number(EXP_TIME_REFRESH_TOKEN_MS)),
      })
      .send({ user });
  }

  @Public()
  @HttpCode(HttpStatus.OK)
  @Post('login')
  @UsePipes(new ValidationPipe())
  async signIn(
    @Body() accessData: AuthDTO,
    @Res({ passthrough: true }) response: Response,
  ) {
    const { access_token, refresh_token, user } = await this.authService
      .signIn(accessData)
      .catch((e) => {
        throw new HttpException(e.message, e.status);
      });

    response
      .cookie('access_token', access_token, {
        httpOnly: true,
        secure: false,
        expires: new Date(Date.now() + Number(EXP_TIME_ACCESS_TOKEN_MS)),
      })
      .cookie('refresh_token', refresh_token, {
        httpOnly: true,
        secure: false,
        expires: new Date(Date.now() + Number(EXP_TIME_REFRESH_TOKEN_MS)),
      })
      .send({ user });
  }

  @Public()
  @HttpCode(HttpStatus.OK)
  @Post('refreshtoken')
  @UsePipes(new ValidationPipe())
  async refreshToken(@Req() request: Request, @Res() response: Response) {
    const refresh_token = request.cookies.refresh_token;

    if (refresh_token === undefined) {
      throw new HttpException('Refresh token not found', HttpStatus.FORBIDDEN);
    }

    const { access_token } = await this.authService
      .refreshToken(refresh_token)
      .catch((e) => {
        throw new HttpException(e.message, e.status);
      });

    response
      .cookie('access_token', access_token, {
        httpOnly: true,
        secure: false,
        expires: new Date(Date.now() + Number(EXP_TIME_ACCESS_TOKEN_MS)),
      })
      .send({ status: 'ok' });
  }

  @HttpCode(HttpStatus.OK)
  @Post('logout')
  async logout(@Res() response: Response) {
    response
      .clearCookie('access_token')
      .clearCookie('refresh_token')
      .send({ status: 'logout succesfully' });
  }

  @HttpCode(HttpStatus.OK)
  @Get('profile')
  profile(@Req() request: any) {
    const user = request.user;
    return { user };
  }
}
