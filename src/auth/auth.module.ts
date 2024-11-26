import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { JwtModule } from '@nestjs/jwt';
import { envs, NATS_SERVICE, USUARIOS_SERVICE } from 'src/config';
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
        name: NATS_SERVICE, 
        transport: Transport.NATS,
        options: {
          servers: envs.natsServers
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
