import { Module } from '@nestjs/common';
import { createAppModuleMetadata } from './app-module.metadata.js';
import { auth } from './auth.js';

@Module(createAppModuleMetadata(auth))
export class AppModule {}
