// Contrato común que deben retornar todos los DAOs de autenticación.
// Mapea los campos necesarios para el JWT de audit.

export interface Sucursal {
  idSede:      string;
  descripcion: string;
}

export interface UserInfo {
  userId:           string;   // → JWT: sub
  username:         string;   // → JWT: username
  roles:            string[]; // → JWT: roles
  email:            string;
  // Datos de display — se incluyen en JWT para /auth/me sin DB lookup
  idUsuario?:       string;
  nombres?:         string;
  apellidoPaterno?: string;
  apellidoMaterno?: string;
  nombreCompleto?:  string;
  nombrePerfil?:    string;
  numeroDocumento?: string;
  sucursales?:      Sucursal[];
  // Token externo — claim privado, nunca expuesto al frontend
  macToken?:               string;
  perfil?:                 string;
  requirePasswordChange?:  boolean;
}
