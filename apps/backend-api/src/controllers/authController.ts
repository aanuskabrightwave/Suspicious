import { Request, Response } from 'express';
import { loginService, registerService } from '../services/authService';

export const login = async (req: Request, res: Response): Promise<void> => {
    try {
        const { email, password }: LoginRequest = req.body;

        const result = await loginService(email, password);
        if (!result.success) {
            res.status(401).json({ error: result.message });
            return;
        }

        res.json(result.data);
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Internal server error during login' });
    }
};

export const register = async (req: Request, res: Response): Promise<void> => {
    try {
        const { email, password, name }: RegisterRequest = req.body;

        const result = await registerService(email, password, name);
        if (!result.success) {
            res.status(400).json({ error: result.message });
            return;
        }

        res.status(201).json(result.data);
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ error: 'Internal server error during registration' });
    }
};