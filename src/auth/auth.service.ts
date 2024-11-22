import { Inject, Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { ClientProxy, RpcException } from '@nestjs/microservices';
import { Repository } from 'typeorm';
import * as bcrypt from 'bcrypt';

import { LoginUserDto, RegisterUserDto } from './dto';
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from './interfaces/jwt-payload.interface';
import { envs, NATS_SERVICE } from 'src/config';
import { InjectRepository } from '@nestjs/typeorm';
import { Auth } from './entities/auth.entity';

@Injectable()
export class AuthService{
  private readonly logger = new Logger('AuthService');

  constructor(
    // @Inject(NATS_SERVICE) private readonly client: ClientProxy,
    @InjectRepository(Auth)
    private readonly userRepository: Repository<Auth>,
    private readonly jwtService: JwtService
  ) {
  }

  async signJWT(payload: JwtPayload) {
    return this.jwtService.sign(payload);
  }

  async verifyToken(token: string) {
    try {
      
      const { sub, iat, exp, ...user } = this.jwtService.verify(token, {
        secret: envs.jwtSecret,
      });

      return {
        user: user,
        token: await this.signJWT(user),
      }

    } catch (error) {
      console.log(error);
      throw new RpcException({
        status: 401,
        message: 'Invalid token'
      })
    }

  }

  async registerUser(registerUserDto: RegisterUserDto) {
    const { nom_contrasena,nom_correo, nom_usuario, ...userData } = registerUserDto;

    try {

      // const position = await this.client.send( 'get_positionById', registerUserDto.idu_rol );

      if( await this.checkEmailExist( nom_correo ) ){
        throw new RpcException({
          status: 400,
          message: 'El correo ya existe',
        });
      }
        
      const user = this.userRepository.create({
        ...userData,
        // nom_correo: this.encryptionService.encrypt(createUserDto.nom_correo),
        // nom_usuario: this.encryptionService.encrypt(createUserDto.nom_usuario),
        nom_correo: registerUserDto.nom_correo,
        nom_usuario: registerUserDto.nom_usuario,
        nom_contrasena: bcrypt.hashSync( nom_contrasena, 10 ),
        idu_rol: registerUserDto.idu_rol
      });

      await this.userRepository.save( user )
      delete user.nom_contrasena;

      // user.nom_correo = this.encryptionService.decrypt(user.nom_correo);
      // user.nom_usuario = this.encryptionService.decrypt(user.nom_usuario);

      const { nom_contrasena: __, ...rest } = user;

      return {
        ...user,
        token: this.signJWT({
          numero_empleado: rest.numero_empleado,
          nom_correo: rest.nom_correo,
          nom_usuario: rest.nom_usuario
        })
      };

    } catch (error) {
      throw new RpcException({
        status: 400,
        message: error.message,
      });
    }
  }

  async loginUser(loginUserDto: LoginUserDto) {
    const { numero_empleado, nom_contrasena } = loginUserDto;

    try {

      const user = await this.userRepository.findOne({
        where: { numero_empleado },
        select: { numero_empleado:true, nom_correo: true, nom_contrasena: true, idu_usuario: true, nom_usuario:true }
      });

      if (!user) {
        throw new RpcException({
          status: 400,
          message: 'Número de empleado no válido',
        });
      }

      const isPasswordValid = bcrypt.compareSync(nom_contrasena, user.nom_contrasena);

      if (!isPasswordValid) {
        throw new RpcException({
          status: 400,
          message: 'Contraseña no válida',
        });
      }

      const { nom_contrasena: __, ...rest } = user;

      return {
        user: rest,
        token: await this.signJWT(rest),
      };
    } catch (error) {
      throw new RpcException({
        status: 400,
        message: error.message,
      });
    }
  }

  private async checkEmailExist(correo: string): Promise<boolean> {
    try {

      const users = await this.userRepository.find();

      const emailExists = users.some(user => 
        user.nom_correo === correo
        // this.encryptionService.decrypt(user.nom_correo) === correo
      );

      return emailExists;
  
    } catch (error) {

      this.handleDBErrors(error);
      return false;
    }
  }

  private handleDBErrors(error: any) {
    const logger = new Logger('DatabaseExceptions'); // Opcional, pero útil para registrar los errores
  
    if (error.code === '23505') {
      logger.warn(`Database error: ${error.detail}`);
      throw new RpcException({ status: 'error', message: error.detail });
    }
  
    logger.error(error); // Log más detallado para errores no previstos
    throw new RpcException({ 
      status: 'error', 
      message: 'Unexpected error, check server logs' 
    });
  }

}
