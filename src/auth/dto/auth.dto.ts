import { IsNotEmpty, IsString } from 'class-validator';

export class AuthDTO {
  @IsNotEmpty()
  @IsString()
  email: string;

  @IsNotEmpty({ message: 'No mi fai' })
  @IsString()
  password: string;
}
