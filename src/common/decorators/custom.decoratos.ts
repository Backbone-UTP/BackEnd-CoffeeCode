import { SetMetadata } from '@nestjs/common';
import { env } from 'process';

export const Public = () => SetMetadata(env.IS_PUBLIC_KEY, true);
