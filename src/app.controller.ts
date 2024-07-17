import { Controller, Get } from '@nestjs/common';

@Controller()
export class AppController {
  @Get('status')
  getHello() {
    return { message: 'API is running 🚀' };
  }
}
