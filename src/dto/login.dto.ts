import { IsString, IsNotEmpty, IsOptional, IsBoolean, MaxLength } from 'class-validator';

export class LoginDto {
  @IsString()
  @IsNotEmpty({ message: 'El usuario es obligatorio' })
  @MaxLength(100)
  username!: string;

  @IsString()
  @IsNotEmpty({ message: 'La contraseña es obligatoria' })
  @MaxLength(128)
  password!: string;

  /**
   * HU01 "Multiples sesiones abiertas" — true cuando el usuario confirmo "Cerrar Sesión"
   * tras recibir un 409 (ActiveSessionExistsException) en un intento de login anterior.
   * Fuerza el cierre de la sesion activa existente (en MAC y en el cache local) antes de
   * emitir la nueva.
   */
  @IsOptional()
  @IsBoolean()
  forceLogout?: boolean;
}

export class CambiarContrasenaDto {
  @IsString()
  @IsNotEmpty({ message: 'La contraseña actual es obligatoria' })
  @MaxLength(128)
  actualContrasena!: string;

  @IsString()
  @IsNotEmpty({ message: 'La nueva contraseña es obligatoria' })
  @MaxLength(128)
  nuevaContrasena!: string;
}
