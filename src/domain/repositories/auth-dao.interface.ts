import type { UserInfo } from '../models/user-info.interface';

/**
 * AUTH_DAO — token para IAuthDao (validación de credenciales).
 * Toda implementación (local, MAC, LDAP) debe cumplir este contrato.
 */
export const AUTH_DAO = Symbol('AUTH_DAO');

/**
 * MAC_DAO — token para IMacAuthDao (operaciones específicas del sistema MAC externo).
 * Solo ExternalAuthDao implementa esta interfaz.
 * Si se usa AuthDao local, este token se registra como NullMacAuthDao.
 *
 * Separación por ISP: AuthDao local NO está obligado a implementar operaciones MAC.
 */
export const MAC_DAO = Symbol('MAC_DAO');

/**
 * Contrato base — validateUser es la única operación que toda implementación debe proveer.
 */
export interface IAuthDao {
  validateUser(username: string, password: string): Promise<UserInfo | null>;
}

/**
 * Contrato extendido para integración con MAC (Módulo de Autenticación Centralizado).
 * Implementado únicamente por ExternalAuthDao.
 * AuthDao (local/env) NO implementa esta interfaz — cumple ISP y LSP.
 */
export interface IMacAuthDao {
  getAccesos(macToken: string, codigoPerfil: string): Promise<any>;
  cerrarSesion(macToken: string, codigoUsuario: string): Promise<any>;
  cambiarContrasena(macToken: string, codigoUsuario: string, actual: string, nueva: string): Promise<any>;
}
