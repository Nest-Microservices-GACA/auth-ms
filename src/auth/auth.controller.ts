import { Controller } from '@nestjs/common';
import { MessagePattern, Payload } from '@nestjs/microservices';
import { AuthService } from './auth.service';
import { CreateAuthDto } from './dto/create-auth.dto';
import { UpdateAuthDto } from './dto/update-auth.dto';

@Controller()
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @MessagePattern('auth.register.user')
  registerUser() {
    return "regiter user";
    // return this.authService.create(createAuthDto);
  }

  @MessagePattern('auth.login.user')
  loginUser() {
    return "login user";
  }

  @MessagePattern('auth.verify.user')
  verifyToken() {
    return "verify user";
  }

}
