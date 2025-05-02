import jwt, { JwtPayload } from "jsonwebtoken";
import * as dotenv from "dotenv";
import { Request, Response, NextFunction } from "express";

dotenv.config();

type DecodedUser = {
  id: string;
  username: string;
  shared: boolean
};

export interface AuthenticatedRequest extends Request {
  user?: DecodedUser;
}

export const authenticateToken = (
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
): void => {
  const authHeader = req.headers['authorization'];
  const token = authHeader?.split(' ')[1]; // Format: "Bearer <token>"

  if (!token) {
    res.status(401).json({ message: 'Access denied. No token provided.' });
    return
  }

  try {
    const decoded = jwt.verify(token, process.env.SECRET_KEY!) as JwtPayload;

    if (decoded && typeof decoded === 'object' && 'id' in decoded && 'username' in decoded) {
      req.user = {
        id: decoded.id,
        username: decoded.username,
        shared: decoded.shared
      };
      next();
    } else {
      res.status(403).json({ message: 'Invalid token structure.' });
      return
    }
  } catch (error) {
    res.status(403).json({ message: 'Invalid token.' });
    return
  }
};
