import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { JwtModule } from '@nestjs/jwt';
import { envs, USUARIOS_SERVICE } from 'src/config';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Auth } from './entities/auth.entity';
import { CommonModule } from './common/common.module';
import { ClientsModule, Transport } from '@nestjs/microservices';

@Module({
  controllers: [AuthController],
  providers: [AuthService],
  imports: [
    TypeOrmModule.forFeature([ Auth ]),
    JwtModule.register({
      // global: true,
      secret: envs.jwtSecret,
      signOptions: { expiresIn: '24h' },
    }),
    ClientsModule.register([
      { 
        name: USUARIOS_SERVICE, 
        transport: Transport.TCP,
        options: {
          host: envs.usuariosMicroserviceHost,
          port: envs.usuariosMicroservicePort
        }
      },
    ]),
    CommonModule
  ],
  exports:[
    TypeOrmModule, JwtModule
  ]
})
export class AuthModule {}
