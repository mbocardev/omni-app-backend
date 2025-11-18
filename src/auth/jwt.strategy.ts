import { ExtractJwt, Strategy } from 'passport-jwt';
import { PassportStrategy } from '@nestjs/passport';
import { Injectable } from '@nestjs/common';
import { jwtConstants } from './constants';

// 'jwt' est le nom par défaut de cette stratégie
@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor() {
    super({
      // 1. Comment extraire le JWT (ici, depuis le header 'Authorization: Bearer <token>')
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),

      // 2. Le secret DOIT correspondre à celui utilisé pour signer le token
      secretOrKey: jwtConstants.secret,

      // 3. Ne pas ignorer l'expiration du token
      ignoreExpiration: false,
    });
  }

  /**
   * Cette méthode est appelée après que Passport a validé la signature du JWT.
   * La "payload" est l'objet que nous avons signé dans AuthService.login().
   * Elle retourne l'objet utilisateur qui sera attaché à req.user.
   */
  async validate(payload: any) {
    // Dans un cas réel, vous pourriez chercher l'utilisateur en BDD ici
    // pour vous assurer qu'il n'a pas été désactivé depuis l'émission du token.
    // Pour l'instant, nous retournons simplement les données du payload :
    return { userId: payload.sub, email: payload.email };
  }
}
