import { Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import { UsersService } from '../users/users.service';
import { User } from '../users/entities/user.entity';

@Injectable()
export class AuthService {
  constructor(
    private usersService: UsersService,
    private jwtService: JwtService,
  ) {}

  /**
   * 1. Vérifie l'email.
   * 2. Compare le mot de passe fourni avec le hachage stocké.
   * (Utilisée par la LocalStrategy)
   */
  async validateUser(email: string, pass: string): Promise<any> {
    const user = await this.usersService.findByEmail(email);

    if (user && (await bcrypt.compare(pass, user.password))) {
      // Si la validation réussit, retourner l'utilisateur sans le mot de passe
      const { password, ...result } = user; 
      return result;
    }
    return null; // Échec de la validation
  }

  /**
   * Génère le JWT après une connexion réussie.
   * Retourne le token JWT.
   */
  async login(user: any) {
    // Le 'user' est le résultat de validateUser (sans le mot de passe)
    const payload = { email: user.email, sub: user.id };

    return {
      access_token: this.jwtService.sign(payload),
    };
  }
}
