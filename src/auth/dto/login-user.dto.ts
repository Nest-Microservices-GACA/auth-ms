import { IsString, Length, MaxLength, MinLength } from 'class-validator';


export class LoginUserDto {

  @IsString()
  @Length(8, 8)
  numero_empleado: string;

  @IsString()
  @MinLength(6)
  @MaxLength(50)
  nom_contrasena: string;


}