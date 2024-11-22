import { Transform } from 'class-transformer';
import { IsEmail, IsNumber, IsOptional, IsString, Matches, MaxLength, MinLength, Validate, ValidationArguments, ValidatorConstraint, ValidatorConstraintInterface } from 'class-validator';

// Validador personalizado para el rango específico
@ValidatorConstraint({ name: 'isInRange', async: false })
class IsInRange implements ValidatorConstraintInterface {
  validate(value: number, args: ValidationArguments): boolean {
    return value >= 90000000 && value < 100000000;
  }

  defaultMessage(args: ValidationArguments): string {
    return 'El valor debe estar entre 90,000,000 and 100,000,000';
  }
}

// Validador personalizado para la longitud del número
@ValidatorConstraint({ name: 'isExactLength', async: false })
class IsExactLength implements ValidatorConstraintInterface {
  validate(value: number, args: ValidationArguments): boolean {
    return value.toString().length === 8;
  }

  defaultMessage(args: ValidationArguments): string {
    return 'Number must be exactly 8 digits long';
  }
}

export class RegisterUserDto {

    @IsString()
    @IsEmail()
    @Matches(/^[^\s@]+@coppel\.com$/, { message: 'El correo debe ser del dominio @coppel.com.' })
    nom_correo: string;

    @IsString()
    @MinLength(6)
    @MaxLength(50)
    @Matches(/^(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&#])[A-Za-z\d@$!%*?&#]{12,}$/, {
      message: 'La contraseña debe tener al menos una letra mayúscula, un número y un carácter especial.'
    })
    nom_contrasena: string;

    @IsString()
    @MinLength(1)
    @Transform(({ value }) => value.trim())
    @Matches(/^[A-ZÁÉÍÓÚÑ][a-záéíóúñ]+(?:\s+[A-ZÁÉÍÓÚÑ][a-záéíóúñ]+){2,}$/, {
      message: 'Escribe nombre completo, con al menos un nombre y dos apellidos, todos comenzando con letra mayúscula'
    })
    nom_usuario: string;

    @IsNumber()
    @Transform(({ value }) => parseInt(value, 10), { toClassOnly: true })
    @Validate(IsExactLength)
    @Validate(IsInRange)
    numero_empleado: string;

    @IsNumber()
    @Transform(({ value }) => parseInt(value, 10))
    idu_rol: number;

    @IsOptional()
    fec_creacion?: Date;
  
    @IsOptional()
    fec_actualizacion?: Date; 

}
